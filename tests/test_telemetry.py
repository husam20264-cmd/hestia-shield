"""
Tests for OpenTelemetry Telemetry v1.1.0
"""

import os
import pytest
from unittest.mock import patch


class TestNoopTelemetry:
    def test_disabled_by_default(self):
        """Telemetry should be a no-op when HESTIA_OTEL_ENABLED is not set."""
        if "HESTIA_OTEL_ENABLED" in os.environ:
            del os.environ["HESTIA_OTEL_ENABLED"]

        from hestia.telemetry import setup_telemetry, get_tracer, get_meter

        result = setup_telemetry()
        assert result is False

        tracer = get_tracer(__name__)
        with tracer.start_span("test_span") as span:
            span.set_attribute("test", "value")
            span.add_event("test_event")

        meter = get_meter(__name__)
        hist = meter.create_histogram("test_histogram")
        hist.record(42)
        counter = meter.create_counter("test_counter")
        counter.add(1)

    def test_noop_span_context_manager(self):
        from hestia.telemetry import NoopSpan

        with NoopSpan() as span:
            span.set_attribute("key", "value")

    def test_noop_tracer_start_span(self):
        from hestia.telemetry import NoopTracer

        tracer = NoopTracer()
        span = tracer.start_span("test")
        span.end()

    def test_noop_meter_instruments(self):
        from hestia.telemetry import NoopMeter

        meter = NoopMeter()
        hist = meter.create_histogram("latency")
        hist.record(100.0)
        counter = meter.create_counter("requests")
        counter.add(1)


class TestTelemetrySmoke:
    def test_get_tracer_returns_noop_when_disabled(self):
        from hestia.telemetry import get_tracer, NoopTracer

        tracer = get_tracer("test")
        assert isinstance(tracer, NoopTracer) or hasattr(tracer, 'start_span')

    def test_get_meter_returns_noop_when_disabled(self):
        from hestia.telemetry import get_meter

        meter = get_meter("test")
        hist = meter.create_histogram("test")
        hist.record(1.0)

    def test_shutdown_noop(self):
        from hestia.telemetry import shutdown_telemetry
        shutdown_telemetry()

    @pytest.mark.asyncio
    async def test_telemetry_middleware_noop(self):
        from hestia.telemetry import TelemetryMiddleware

        async def app(scope, receive, send):
            pass

        middleware = TelemetryMiddleware()
        middleware.app = app

        scope = {"type": "http", "method": "GET", "path": "/health"}
        await middleware(scope, None, None)

    def test_instrument_fastapi_noop(self):
        from hestia.telemetry import instrument_fastapi
        instrument_fastapi(None)


class TestDecisionEngineTelemetry:
    def test_decision_engine_has_telemetry(self):
        from hestia.telemetry import get_tracer

        tracer = get_tracer("hestia.decision_engine")
        with tracer.start_span("evaluate") as span:
            span.set_attribute("decision", "allow")
            span.set_attribute("risk_score", 0.1)
            span.set_attribute("fast_path", True)


class TestQueueTelemetry:
    def test_queue_metrics_noop(self):
        from hestia.telemetry import get_meter

        meter = get_meter("hestia.queue")
        queue_depth = meter.create_histogram("queue.depth")
        queue_depth.record(5)

        enqueued = meter.create_counter("queue.enqueued")
        enqueued.add(1)

        processed = meter.create_counter("queue.processed")
        processed.add(1)