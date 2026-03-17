# ── Stage 1: Build frontend ───────────────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ .
RUN npm run build

# ── Stage 2: Python runtime ───────────────────────────────────────────────────
FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/mockdr/mockdr"
LABEL org.opencontainers.image.description="Multi-EDR & SIEM mock server"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY --from=frontend-build /app/dist ./frontend/dist

WORKDIR /app/backend
# Health check uses the S1 system/status endpoint; CrowdStrike, MDE, and Elastic
# Security endpoints are also available on the same port.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:5001/web/api/v2.1/system/status')"]
RUN adduser --disabled-password --gecos '' appuser
USER appuser

CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "5001"]
