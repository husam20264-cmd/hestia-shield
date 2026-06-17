"""
OpenTelemetry Observability for Hestia Shield v1.1.0

Provides tracing, metrics, and logging with no-op fallback when OTEL is disabled.
Usage:
    from .telemetry import setup_telemetry, get_tracer, get_meter

    setup_telemetry()
    tracer = get_tracer(__name__)
    meter = get_meter(__name__)
"""

import os
import logging
from typing import Optional, Dict, Any
from functools import wraps

logger = logging.getLogger(__name__)

_ENABLED = False
_TRACER_PROVIDER = None
_METER_PROVIDER = None
_TRACER = None
_METER = None


def _is_enabled() -> bool:
    return os.getenv("HESTIA_OTEL_ENABLED", "false").lower() in ("true", "1", "yes")


def setup_telemetry() -> bool:
    global _ENABLED, _TRACER_PROVIDER, _METER_PROVIDER, _TRACER, _METER

    if not _is_enabled():
        logger.info("OpenTelemetry disabled (set HESTIA_OTEL_ENABLED=true to enable)")
        _ENABLED = False
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

        service_name = os.getenv("HESTIA_OTEL_SERVICE_NAME", "hestia-shield")
        endpoint = os.getenv("HESTIA_OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

        resource = Resource.create({"service.name": service_name})

        if os.getenv("HESTIA_OTEL_TRACES", "true").lower() in ("true", "1", "yes"):
            tracer_provider = TracerProvider(resource=resource)
            span_exporter = OTLPSpanExporter(endpoint=endpoint)
            span_processor = BatchSpanProcessor(span_exporter)
            tracer_provider.add_span_processor(span_processor)
            trace.set_tracer_provider(tracer_provider)
            _TRACER_PROVIDER = tracer_provider
            _TRACER = trace.get_tracer(service_name)
            logger.info(f"OTEL tracing enabled, exporting to {endpoint}")
        else:
            from opentelemetry import trace
            _TRACER = trace.get_tracer(service_name)

        if os.getenv("HESTIA_OTEL_METRICS", "true").lower() in ("true", "1", "yes"):
            metric_exporter = OTLPMetricExporter(endpoint=endpoint)
            metric_reader = PeriodicExportingMetricReader(metric_exporter)
            meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
            _METER_PROVIDER = meter_provider
            _METER = meter_provider.get_meter(service_name)
            logger.info(f"OTEL metrics enabled, exporting to {endpoint}")

        _ENABLED = True
        return True

    except ImportError as e:
        logger.warning(f"OpenTelemetry packages not installed: {e}. Telemetry disabled.")
        _ENABLED = False
        return False
    except Exception as e:
        logger.warning(f"OpenTelemetry setup failed: {e}. Telemetry disabled.")
        _ENABLED = False
        return False


def get_tracer(name: Optional[str] = None) -> Any:
    global _TRACER
    if not _ENABLED:
        return NoopTracer()
    if not _TRACER:
        try:
            from opentelemetry import trace
            _TRACER = trace.get_tracer(name or "hestia-shield")
        except ImportError:
            return NoopTracer()
    return _TRACER


def get_meter(name: Optional[str] = None) -> Any:
    global _METER
    if not _ENABLED or not _METER:
        return NoopMeter()
    return _METER


def instrument_fastapi(app) -> None:
    """Instrument FastAPI app with OpenTelemetry middleware if enabled."""
    if not _ENABLED:
        return

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        FastAPIInstrumentor.instrument_app(app)
        logger.info("FastAPI instrumented with OpenTelemetry")
    except ImportError:
        logger.debug("FastAPIInstrumentor not available, skipping")
    except Exception as e:
        logger.warning(f"FastAPI instrumentation failed: {e}")


def instrument_httpx() -> None:
    """Instrument httpx client if enabled."""
    if not _ENABLED:
        return

    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()
        logger.info("httpx instrumented with OpenTelemetry")
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"httpx instrumentation failed: {e}")


class NoopSpan:
    """No-op span that does nothing."""
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def set_attribute(self, key, value): pass
    def set_status(self, status, description=None): pass
    def add_event(self, name, attributes=None): pass
    def record_exception(self, exception): pass
    def end(self): pass


class NoopTracer:
    def start_span(self, name, *args, **kwargs): return NoopSpan()
    def start_as_current_span(self, name, *args, **kwargs):
        return NoopSpan()


class NoopHistogram:
    def record(self, amount, attributes=None): pass
    def bind(self, attributes=None): return self


class NoopCounter:
    def add(self, amount, attributes=None): pass
    def bind(self, attributes=None): return self


class NoopMeter:
    def create_histogram(self, name, *args, **kwargs): return NoopHistogram()
    def create_counter(self, name, *args, **kwargs): return NoopCounter()
    def create_up_down_counter(self, name, *args, **kwargs): return NoopCounter()


def shutdown_telemetry() -> None:
    """Gracefully shut down telemetry exporters."""
    global _TRACER_PROVIDER, _METER_PROVIDER

    if _TRACER_PROVIDER and hasattr(_TRACER_PROVIDER, "shutdown"):
        try:
            _TRACER_PROVIDER.shutdown()
            logger.debug("Tracer provider shut down")
        except Exception as e:
            logger.warning(f"Tracer provider shutdown error: {e}")

    if _METER_PROVIDER and hasattr(_METER_PROVIDER, "shutdown"):
        try:
            _METER_PROVIDER.shutdown()
            logger.debug("Meter provider shut down")
        except Exception as e:
            logger.warning(f"Meter provider shutdown error: {e}")


class TelemetryMiddleware:
    """ASGI middleware that adds request_id to request scope for tracing."""

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        import uuid
        request_id = str(uuid.uuid4())[:16]
        scope["request_id"] = request_id

        tracer = get_tracer(__name__)
        with tracer.start_as_current_span(f"{scope.get('method', 'UNKNOWN')} {scope.get('path', '/')}"):
            await self.app(scope, receive, send)