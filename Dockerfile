# ── Stage 1: Build frontend ───────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
# Vite inlines import.meta.env.VITE_* at build time. Without a .env the UI
# would ship with undefined credentials and 401 against every vendor, so fall
# back to the mock defaults when the build context carries no .env.
RUN [ -f .env ] || cp .env.example .env
RUN npm run build

# ── Stage 2: Python runtime ───────────────────────────────────────────────────
FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/mockdr/mockdr"
LABEL org.opencontainers.image.description="Multi-EDR & SIEM mock server"
LABEL org.opencontainers.image.licenses="LicenseRef-BSL-1.1"
WORKDIR /app

# The base image lags Debian's security updates, so it ships known-vulnerable
# OS packages between tag refreshes — util-linux alone accounted for 36 HIGH
# CVEs that already had fixes published. Upgrading at build time picks those up
# without waiting for a new base tag.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY --from=frontend-build /app/dist ./frontend/dist

WORKDIR /app/backend
# Health check uses the S1 system/status endpoint; CrowdStrike, MDE, and Elastic
# Security endpoints are also available on the same port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5001/web/api/v2.1/system/status')"]
# The user is created after the COPYs, so own what was copied: a
# MOCKDR_PERSIST path inside the image must be writable by the process.
RUN adduser --disabled-password --gecos '' appuser && chown -R appuser:appuser /app
USER appuser

# `--no-server-header`: uvicorn adds `Server: uvicorn` after the app has
# answered, and the mounts that name their own server cannot remove it
# from inside. Splunkd calls itself Splunkd; Elasticsearch and Kibana
# name no server at all.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5001", "--no-server-header"]
