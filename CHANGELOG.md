# Changelog

## [1.1.0] - 2026-06-19

**Enterprise Deployment Release**

Hestia Shield v1.1.0 adds enterprise deployment infrastructure on top of the v1.0.0 Production Ready runtime security engine.

This release focuses on production-grade storage, background processing, observability, containerization, and Kubernetes deployment support.

### Added

#### PostgreSQL Async Storage

- Added PostgreSQL async storage backend.
- Added SQLAlchemy async storage support.
- Added `asyncpg` support for production database connections.
- Added environment-based database selection through `HESTIA_DATABASE_URL`.
- Added SQLite fallback for local and development environments.
- Added persistent support for:
  - tenants
  - api_keys
  - security_events
  - audit_logs
  - webhooks
  - alerts
  - daily_stats
  - agent_profiles

#### Redis Queue

- Added Redis-backed priority queue for background tasks.
- Added Task and Worker abstractions.
- Added queue handlers for:
  - webhooks
  - audit events
  - security events
- Added NullQueue fallback when Redis is unavailable.
- Added singleton queue lifecycle to preserve handlers across API calls.
- Added support for both async and ThreadPoolExecutor execution contexts.

#### OpenTelemetry

- Added optional OpenTelemetry observability layer.
- Added FastAPI middleware instrumentation.
- Added decision engine spans.
- Added queue operation metrics.
- Added no-op fallback when telemetry is disabled.
- Added graceful fallback when OpenTelemetry dependencies are missing.
- Added optional install extra:

  ```
  pip install hestia-shield[otel]
  ```

Supported environment variables:

```
HESTIA_OTEL_ENABLED=true
HESTIA_OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317
HESTIA_OTEL_TRACES=true
HESTIA_OTEL_METRICS=true
HESTIA_OTEL_SERVICE_NAME=hestia-shield
```

#### Docker

- Added production Dockerfile.
- Added multi-stage Docker build.
- Added non-root runtime user.
- Added `/health` Docker healthcheck.
- Added Gunicorn + Uvicorn worker runtime command.
- Added Docker Compose support for:
  - Hestia Shield API
  - PostgreSQL
  - Redis
  - OpenTelemetry collector

#### Kubernetes

- Added Helm chart for Kubernetes deployment.
- Added Kustomize overlays.
- Added Kubernetes deployment manifests.
- Added Service, ConfigMap, and Secret support.
- Added PostgreSQL and Redis deployment configuration.
- Added OpenTelemetry configuration support.
- Added readiness and liveness probe configuration.
- Added resource requests and limits.

### Changed

- Improved production deployment architecture.
- Improved queue lifecycle handling.
- Improved background task isolation from request path.
- Improved runtime deployment defaults.
- Updated project documentation for enterprise deployment.

### Fixed

- Fixed queue handler persistence by using a singleton queue pattern.
- Fixed "No handler registered" warnings caused by creating new queue instances per call.
- Fixed queue behavior across ThreadPoolExecutor and async execution contexts.
- Improved fallback behavior when Redis is not configured.
- Improved fallback behavior when OpenTelemetry dependencies are not installed.

### Validation

Final validation results:

| Test suite | Result |
|------------|--------|
| Core tests | 49/49 passed |
| Performance tests | 2/2 passed |
| Benchmark tests | 2/2 passed |
| **Total** | **53/53 passed** |

### Release Status

- v1.1.0 = Enterprise Deployment Release Candidate
- Target after final release validation = Enterprise Deployment Ready

### Non-Blocking Follow-Ups

- Run `helm lint`.
- Run `helm template`.
- Add kubeconform or kubescape manifest validation.
- Add production Grafana dashboards.
- Add Prometheus alert rules.
- Add release automation for GitHub tags and releases.

---

## [1.0.0] - 2026-06-19

**Production Ready - Low-Latency Runtime Architecture**

### Architecture

- Added Fast Path for low-risk requests.
- Added parallel full evaluation.
- Added timeout-bounded security components.
- Added decision aggregation.
- Moved audit, analytics, and webhook side effects out of the critical path.

### Performance

- Fast Path target: under 50ms in validated test environment.
- Full Path target: under 150ms in validated test environment.
- Added performance and benchmark test suites.
- Added component-level timing.

### Infrastructure

- Added optional Redis cache.
- Added NullCache fallback.
- Added buffered audit logging.
- Added queued webhook delivery design.

### Testing

- Added performance tests.
- Added benchmark tests.
- Validated 32/32 tests passing.

---

## [0.4.1] - 2026-06-18

**Webhooks + Incident Notifications**

- Added webhook subscriptions.
- Added incident notifications.
- Added webhook delivery logs.
- Added HMAC webhook signatures.
- Added webhook test endpoint.

---

## [0.4.0] - 2026-06-18

**JWT Hardening + Rate Limiting + Pagination**

- Removed raw API key from JWT payload.
- Added JWT payload hardening.
- Added rate limiting.
- Added pagination for list endpoints.

---

## [0.3.1] - 2026-06-17

**Security Patch**

- Added hashed API keys.
- Added tenant-scoped API key creation.
- Added audit log.
- Added CORS configuration.
- Added RBAC tests.

---

## [0.3.0] - 2026-06-17

**Persistent Storage + JWT Auth + RBAC + Analytics**

- Added persistent storage.
- Added JWT authentication.
- Added role-based access control.
- Added analytics endpoints.
- Added compliance reporting.

---

## [0.2.1] - 2026-06-16

**AgentMonitor Stabilized**

- Improved agent monitoring.
- Added alert resolution.
- Added agent summaries.
- Added production risk and pattern shift detection.

---

## [0.2.0] - 2026-06-16

**AgentMonitor Initial**

- Added agent behavior monitoring.
- Added detection for suspicious tool-call sequences.
- Added alerts API.

---

## [0.1.0] - 2026-06-15

**Initial Core Release**

- Added core decision engine.
- Added rules engine.
- Added classifier.
- Added attack memory.
- Added API server.
- Added basic examples and tests.
