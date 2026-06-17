# Hestia Shield v1.1.0 Release Notes

**Enterprise Deployment Release**

Hestia Shield v1.1.0 is the Enterprise Deployment release of Hestia Shield.

This release builds on the v1.0.0 Production Ready runtime security engine and adds the infrastructure required for enterprise deployment, observability, background processing, containerization, and Kubernetes-based operations.

## Release Status

| Item | Status |
|------|--------|
| Version | v1.1.0 |
| Release type | Enterprise Deployment |
| Stability | Release Candidate |
| Previous stable | v1.0.0 |
| Test status | 53/53 passed |
| Target rating | 9.5/10 after release validation |

## What's New

### 1. PostgreSQL Async Storage

Hestia Shield now supports PostgreSQL as a production-grade persistent storage backend.

The system keeps SQLite as the default local/development storage option, while enabling PostgreSQL for production deployments through environment-based configuration.

Included tables:
- tenants
- api_keys
- security_events
- audit_logs
- webhooks
- alerts
- daily_stats
- agent_profiles

Key capabilities:
- Async SQLAlchemy storage layer
- PostgreSQL support through `HESTIA_DATABASE_URL`
- SQLite fallback for local development
- Storage parity across supported backends
- Production-ready persistence for audit, events, webhooks, tenants, and API keys

### 2. Redis Queue for Background Processing

v1.1.0 introduces a Redis-backed priority queue for background tasks.

This moves non-critical side effects out of the request path, including webhook delivery, audit processing, and event handling.

Key capabilities:
- RedisQueue using sorted sets
- Priority-based task ordering
- Task model and worker execution flow
- Webhook, audit, and event handlers
- NullQueue fallback when Redis is unavailable
- Singleton queue lifecycle to preserve registered handlers

Architecture:

```
HESTIA_REDIS_URL set → RedisQueue
No Redis             → NullQueue
```

### 3. OpenTelemetry Observability

Hestia Shield now includes optional OpenTelemetry instrumentation for production observability.

Telemetry is designed to be safe by default. If disabled or if OpenTelemetry dependencies are missing, Hestia Shield falls back to no-op behavior without breaking runtime execution.

Key capabilities:
- FastAPI request instrumentation
- Decision engine spans
- Queue operation metrics
- Optional traces and metrics
- No-op fallback when disabled
- Graceful handling when dependencies are missing
- Optional install via `hestia-shield[otel]`

Environment variables:

```
HESTIA_OTEL_ENABLED=true
HESTIA_OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
HESTIA_OTEL_TRACES=true
HESTIA_OTEL_METRICS=true
HESTIA_OTEL_SERVICE_NAME=hestia-shield
```

### 4. Docker Containerization

v1.1.0 adds production-oriented Docker support.

The Dockerfile uses a multi-stage build to separate build-time dependencies from the runtime image.

Highlights:
- Builder stage for package installation and native dependencies
- Runtime stage based on `python:3.11-slim`
- Non-root `hestia` user
- Healthcheck using `/health`
- Gunicorn with Uvicorn workers
- Docker Compose setup for API, PostgreSQL, Redis, and OTEL collector

Quick start:

```bash
docker compose up -d
curl http://localhost:8000/health
```

### 5. Kubernetes Deployment

v1.1.0 includes Kubernetes deployment support through Helm charts and Kustomize overlays.

Included deployment capabilities:
- Helm chart
- Kustomize overlays
- Deployment manifests
- Service definitions
- ConfigMap and Secret support
- PostgreSQL and Redis configuration
- OpenTelemetry configuration
- Health probes
- Resource limits and requests
- Enterprise deployment baseline

## Validation

Final test results:

| Test suite | Result |
|------------|--------|
| Core tests | 49/49 passed |
| Performance tests | 2/2 passed |
| Benchmark tests | 2/2 passed |
| **Total** | **53/53 passed** |

## Current Release State

- v1.0.0 = Production Ready
- v1.1.0 = Enterprise Deployment Release Candidate

After release notes, changelog, Helm validation, GitHub tag, and GitHub release are complete:
- v1.1.0 = Enterprise Deployment Ready

## Known Non-Blocking Follow-Ups

The following items do not block v1.1.0 but should be completed during release finalization or post-release validation:

- Run `helm lint`
- Run `helm template`
- Add kubeconform or kubescape validation for Kubernetes manifests
- Clean redundant environment/secret entries where applicable
- Add release automation in CI
- Add production Grafana dashboards and Prometheus alert rules

## Upgrade Notes

v1.1.0 is designed to remain compatible with v1.0.0 runtime behavior while adding enterprise deployment infrastructure.

Recommended production configuration:

```bash
HESTIA_DATABASE_URL=postgresql+asyncpg://hestia:password@postgres:5432/hestia
HESTIA_REDIS_URL=redis://redis:6379/0
HESTIA_OTEL_ENABLED=true
HESTIA_OTEL_SERVICE_NAME=hestia-shield
```

## Final Release Decision

Hestia Shield v1.1.0 is approved as the Enterprise Deployment release candidate.

It is ready for final release packaging, Helm validation, GitHub tagging, and GitHub release publication.
