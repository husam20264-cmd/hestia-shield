# ============================================================
# Hestia Shield v2.0.0 — Production Docker Image
# Multi-stage build: builder → runtime
# ============================================================

# ---- Stage 1: Builder ----
FROM python:3.13-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

COPY hestia/ ./hestia/
COPY examples/ ./examples/
COPY data/ ./data/

# ---- Stage 2: Runtime ----
FROM python:3.13-slim AS runtime

LABEL org.opencontainers.image.title="Hestia Shield"
LABEL org.opencontainers.image.description="Runtime Security for AI Agents"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r hestia && useradd -r -g hestia -d /app -s /sbin/nologin hestia

WORKDIR /app

COPY --from=builder /root/.local /root/.local
COPY --from=builder /build/hestia/ ./hestia/
COPY --from=builder /build/examples/ ./examples/
COPY --from=builder /build/data/ ./data/

RUN mkdir -p /etc/hestia/plugins && chown hestia:hestia /etc/hestia/plugins

ENV PATH=/root/.local/bin:$PATH \
    PYTHONPATH=/app \
    HESTIA_DATA_DIR=/app/data \
    HESTIA_HOST=0.0.0.0 \
    HESTIA_PORT=8000 \
    HESTIA_PLUGIN_DIR=/etc/hestia/plugins

USER hestia

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 -c "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/health').read().decode())" || exit 1

EXPOSE 8000

CMD ["gunicorn", "hestia.api:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--max-requests", "10000", \
     "--max-requests-jitter", "1000", \
     "--timeout", "30", \
     "--keep-alive", "5", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
