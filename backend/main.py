from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.auth import require_admin, require_auth
from api.middleware.audit import RequestAuditMiddleware
from api.middleware.fault_injection import FaultInjectionMiddleware
from api.middleware.metrics import MetricsMiddleware
from api.middleware.proxy import RecordingProxyMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.request_logging import RequestLoggingMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.routers import (
    accounts,
    activities,
    agents,
    alerts,
    deep_visibility,
    dev,
    device_control,
    docs,
    exclusions,
    firewall,
    groups,
    hashes,
    ioc,
    policies,
    sites,
    system,
    tags,
    threats,
    users,
    webhook_sink,
    webhooks,
)
from api.routers import (
    cs_auth as cs_auth_router,
)
from api.routers import (
    cs_cases as cs_cases_router,
)
from api.routers import (
    cs_detections as cs_detections_router,
)
from api.routers import (
    cs_discover as cs_discover_router,
)
from api.routers import (
    cs_host_groups as cs_host_groups_router,
)
from api.routers import (
    cs_hosts as cs_hosts_router,
)
from api.routers import (
    cs_incidents as cs_incidents_router,
)
from api.routers import (
    cs_iocs as cs_iocs_router,
)
from api.routers import (
    cs_legacy_iocs as cs_legacy_iocs_router,
)
from api.routers import (
    cs_processes as cs_processes_router,
)
from api.routers import (
    cs_quarantine as cs_quarantine_router,
)
from api.routers import (
    cs_users as cs_users_router,
)
from api.routers import (
    es_alerts as es_alerts_router,
)
from api.routers import (
    es_auth as es_auth_router,
)
from api.routers import (
    es_cases as es_cases_router,
)
from api.routers import (
    es_endpoints as es_endpoints_router,
)
from api.routers import (
    es_exception_lists as es_exception_lists_router,
)
from api.routers import (
    es_rules as es_rules_router,
)
from api.routers import (
    es_search as es_search_router,
)
from api.routers import (
    mde_advanced_hunting as mde_advanced_hunting_router,
)
from api.routers import (
    mde_alerts as mde_alerts_router,
)
from api.routers import (
    mde_auth as mde_auth_router,
)
from api.routers import (
    mde_file_info as mde_file_info_router,
)
from api.routers import (
    mde_indicators as mde_indicators_router,
)
from api.routers import (
    mde_investigations as mde_investigations_router,
)
from api.routers import (
    mde_machine_actions as mde_machine_actions_router,
)
from api.routers import (
    mde_machines as mde_machines_router,
)
from api.routers import (
    mde_software as mde_software_router,
)
from api.routers import (
    mde_users as mde_users_router,
)
from api.routers import (
    mde_vulnerabilities as mde_vulnerabilities_router,
)
from api.routers import (
    metrics as metrics_router,
)
from api.routers import (
    proxy as proxy_router,
)
from api.routers import (
    xdr_actions as xdr_actions_router,
)
from api.routers import (
    xdr_alerts as xdr_alerts_router,
)
from api.routers import (
    xdr_audit as xdr_audit_router,
)
from api.routers import (
    xdr_distributions as xdr_distributions_router,
)
from api.routers import (
    xdr_endpoints as xdr_endpoints_router,
)
from api.routers import (
    xdr_hash_exceptions as xdr_hash_exceptions_router,
)
from api.routers import (
    xdr_incidents as xdr_incidents_router,
)
from api.routers import (
    xdr_iocs as xdr_iocs_router,
)
from api.routers import (
    xdr_scripts as xdr_scripts_router,
)
from api.routers import (
    xdr_system as xdr_system_router,
)
from api.routers import (
    xdr_xql as xdr_xql_router,
)
from api.routers.sentinel import (
    sentinel_alert_rules as sentinel_alert_rules_router,
)
from api.routers.sentinel import (
    sentinel_auth as sentinel_auth_router,
)
from api.routers.sentinel import (
    sentinel_bookmarks as sentinel_bookmarks_router,
)
from api.routers.sentinel import (
    sentinel_data_connectors as sentinel_data_connectors_router,
)
from api.routers.sentinel import (
    sentinel_incidents as sentinel_incidents_router,
)
from api.routers.sentinel import (
    sentinel_log_analytics as sentinel_log_analytics_router,
)
from api.routers.sentinel import (
    sentinel_operations as sentinel_operations_router,
)
from api.routers.sentinel import (
    sentinel_threat_intel as sentinel_threat_intel_router,
)
from api.routers.sentinel import (
    sentinel_watchlists as sentinel_watchlists_router,
)
from api.routers.splunk import (
    splunk_alerts as splunk_alerts_router,
)
from api.routers.splunk import (
    splunk_auth as splunk_auth_router,
)
from api.routers.splunk import (
    splunk_hec as splunk_hec_router,
)
from api.routers.splunk import (
    splunk_indexes as splunk_indexes_router,
)
from api.routers.splunk import (
    splunk_inputs as splunk_inputs_router,
)
from api.routers.splunk import (
    splunk_kvstore as splunk_kvstore_router,
)
from api.routers.splunk import (
    splunk_notable as splunk_notable_router,
)
from api.routers.splunk import (
    splunk_saved_searches as splunk_saved_searches_router,
)
from api.routers.splunk import (
    splunk_search as splunk_search_router,
)
from api.routers.splunk import (
    splunk_server as splunk_server_router,
)
from config import API_PREFIX, CORS_ORIGINS, PERSIST_PATH
from infrastructure import seed
from utils.logging import setup_logging

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Seed or load persisted state on startup; flush on shutdown."""
    pm = None
    if PERSIST_PATH:
        from infrastructure.persistence import init_persistence, notify_mutation
        from repository.store import store
        pm = init_persistence(PERSIST_PATH)
        loaded = pm.load_if_exists()
        if not loaded:
            seed.generate_all()
        store._on_mutate = notify_mutation
    else:
        seed.generate_all()
    yield
    if pm is not None:
        pm.flush()


app = FastAPI(
    title="SentinelOne Mock API",
    description="Full-fidelity SentinelOne Management Console API v2.1 mock server",
    version="2.1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=[
        "Authorization", "Content-Type", "Accept", "kbn-xsrf",
        "x-xdr-auth-id", "x-xdr-nonce", "x-xdr-timestamp",
    ],
)

# Middleware registration order: last added = outermost wrapper.
# RequestLoggingMiddleware runs first (outermost), then RateLimit, Security, Audit, Proxy innermost.
app.add_middleware(RecordingProxyMiddleware)  # innermost — added first, runs last
app.add_middleware(FaultInjectionMiddleware)  # fault injection — delay/errors before proxy
app.add_middleware(TenantScopeMiddleware)     # tenant isolation — scope non-admin queries
app.add_middleware(RequestAuditMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(MetricsMiddleware)         # outermost — runs first, captures all timings


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return a SentinelOne-style JSON error response for all HTTP errors.

    If the handler already carries a dict detail (e.g. the auth module),
    use it verbatim.  Otherwise synthesise an S1-shaped envelope.
    """
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    # Map status codes to S1-style error codes: <status><domain>0
    code = exc.status_code * 10000 + 10
    titles = {400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
              404: "Not Found", 422: "Unprocessable Entity", 429: "Too Many Requests"}
    title = titles.get(exc.status_code, "Error")
    detail_msg = exc.detail if isinstance(exc.detail, str) else title
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "errors": [{"code": code, "detail": detail_msg, "title": title}],
            "data": None,
        },
    )


# ── Metrics (no auth, no prefix — mounted at /metrics) ───────────────────────
app.include_router(metrics_router.router)

# ── Public (no auth) ──────────────────────────────────────────────────────────
app.include_router(docs.router, prefix=API_PREFIX)
app.include_router(system.public_router, prefix=API_PREFIX)
app.include_router(webhook_sink.public_router, prefix=API_PREFIX)

# ── Authenticated (read-only is fine) ─────────────────────────────────────────
_AUTH = [Depends(require_auth)]

# Read-only endpoints — any authenticated role
for module in [system, agents, threats, alerts, activities, accounts, sites,
               groups, exclusions, policies, firewall, device_control, hashes,
               ioc, tags, deep_visibility]:
    app.include_router(module.router, prefix=API_PREFIX, dependencies=_AUTH)

# Write endpoints are guarded per-handler via Depends(require_write) or
# Depends(require_admin) inside the router files themselves.  The router-level
# dependency only ensures the caller is authenticated; the handler-level
# dependency adds role checks on mutating endpoints.

# User management + webhooks + proxy — admin guard on mutations inside router
for module in [users, webhooks, proxy_router]:
    app.include_router(module.router, prefix=API_PREFIX, dependencies=_AUTH)

# Dev endpoints — admin only
app.include_router(dev.router, prefix=API_PREFIX, dependencies=[Depends(require_admin)])
app.include_router(webhook_sink.router, prefix=API_PREFIX, dependencies=[Depends(require_admin)])

# ── CrowdStrike Falcon mock endpoints (mounted at /cs) ────────────────────────
CS_PREFIX = "/cs"

# OAuth token endpoint — no auth required
app.include_router(cs_auth_router.router, prefix=CS_PREFIX)

# Authenticated CS endpoints — each handler applies its own auth dependency
for _cs_module in [
    cs_hosts_router,
    cs_detections_router,
    cs_incidents_router,
    cs_iocs_router,
    cs_legacy_iocs_router,
    cs_host_groups_router,
    cs_users_router,
    cs_processes_router,
    cs_quarantine_router,
    cs_cases_router,
    cs_discover_router,
]:
    app.include_router(_cs_module.router, prefix=CS_PREFIX)

# ── Microsoft Defender for Endpoint mock endpoints (mounted at /mde) ──────────
MDE_PREFIX = "/mde"

# OAuth token endpoint — no auth required
app.include_router(mde_auth_router.router, prefix=MDE_PREFIX)

# Authenticated MDE endpoints — each handler applies its own auth dependency
for _mde_module in [
    mde_machines_router,
    mde_alerts_router,
    mde_indicators_router,
    mde_machine_actions_router,
    mde_investigations_router,
    mde_advanced_hunting_router,
    mde_software_router,
    mde_vulnerabilities_router,
    mde_file_info_router,
    mde_users_router,
]:
    app.include_router(_mde_module.router, prefix=MDE_PREFIX)


# Mock export data endpoint (SoftwareInventoryExport; no auth — SAS pre-signed)
@app.get("/_mock/mde/software-export-data.json")
def mde_software_export_data() -> list[dict]:
    """Serve the MDE software inventory export data (mock SAS download)."""
    from application.mde_machines import queries as mq
    return mq.get_software_export_data()


# ── Elastic Security mock endpoints ──────────────────────────────────────────
ES_PREFIX = "/elastic"
KBN_PREFIX = "/kibana"

# Elasticsearch REST API — token endpoint + search (no prefix auth; each handler guards itself)
app.include_router(es_auth_router.router, prefix=ES_PREFIX)
app.include_router(es_search_router.router, prefix=ES_PREFIX)

# Kibana Security API endpoints — each handler applies its own auth dependency
for _es_module in [
    es_endpoints_router,
    es_rules_router,
    es_alerts_router,
    es_cases_router,
    es_exception_lists_router,
]:
    app.include_router(_es_module.router, prefix=KBN_PREFIX)

# ── Cortex XDR mock endpoints (mounted at /xdr/public_api/v1) ────────────────
XDR_PREFIX = "/xdr/public_api/v1"

# All XDR endpoints — each handler applies its own auth dependency via require_xdr_auth
for _xdr_module in [
    xdr_incidents_router,
    xdr_alerts_router,
    xdr_endpoints_router,
    xdr_scripts_router,
    xdr_iocs_router,
    xdr_actions_router,
    xdr_hash_exceptions_router,
    xdr_audit_router,
    xdr_distributions_router,
    xdr_xql_router,
    xdr_system_router,
]:
    app.include_router(_xdr_module.router, prefix=XDR_PREFIX)

# ── Splunk SIEM mock endpoints (mounted at /splunk) ─────────────────────────
SPLUNK_PREFIX = "/splunk"

# Auth login — no auth required
app.include_router(splunk_auth_router.router, prefix=SPLUNK_PREFIX)

# Server info — no auth required (health checks)
app.include_router(splunk_server_router.router, prefix=SPLUNK_PREFIX)

# HEC endpoints — HEC token auth (separate from session auth)
app.include_router(splunk_hec_router.router, prefix=SPLUNK_PREFIX)

# Authenticated Splunk endpoints — each handler applies its own auth dependency
for _splunk_module in [
    splunk_search_router,
    splunk_saved_searches_router,
    splunk_notable_router,
    splunk_kvstore_router,
    splunk_indexes_router,
    splunk_alerts_router,
    splunk_inputs_router,
]:
    app.include_router(_splunk_module.router, prefix=SPLUNK_PREFIX)

# ── Microsoft Sentinel mock endpoints (mounted at /sentinel) ─────────────────
SENTINEL_PREFIX = "/sentinel"

# OAuth2 token + operations — no auth required
app.include_router(sentinel_auth_router.router, prefix=SENTINEL_PREFIX)
app.include_router(sentinel_operations_router.router, prefix=SENTINEL_PREFIX)

# Log Analytics query endpoint (separate path, auth required)
app.include_router(sentinel_log_analytics_router.router, prefix=SENTINEL_PREFIX)

# Authenticated Sentinel endpoints — each handler applies its own auth dependency
for _sentinel_module in [
    sentinel_incidents_router,
    sentinel_alert_rules_router,
    sentinel_watchlists_router,
    sentinel_threat_intel_router,
    sentinel_bookmarks_router,
    sentinel_data_connectors_router,
]:
    app.include_router(_sentinel_module.router, prefix=SENTINEL_PREFIX)

# ── Frontend (SPA) — only active when frontend/dist exists ────────────────────
_DIST = Path(__file__).parent.parent / "frontend" / "dist"

if _DIST.exists():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str = "") -> FileResponse:
        """Serve the SPA index.html for all unmatched routes."""
        return FileResponse(_DIST / "index.html")


def _cli() -> None:
    """CLI entrypoint for ``mockdr`` command."""
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
