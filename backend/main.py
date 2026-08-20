from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from json import JSONDecodeError
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.routing import Match

from api.auth import require_admin, require_auth
from api.middleware.audit import RequestAuditMiddleware
from api.middleware.fault_injection import FaultInjectionMiddleware
from api.middleware.head_method import HeadMethodMiddleware
from api.middleware.metrics import MetricsMiddleware
from api.middleware.proxy import RecordingProxyMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.request_logging import RequestLoggingMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.middleware.splunk_namespace import SplunkNamespaceMiddleware
from api.middleware.splunk_output_mode import SplunkOutputModeMiddleware
from api.middleware.splunk_paging import SplunkPagingMiddleware
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
from api.routers.graph import (
    app_protection as graph_app_protection_router,
)
from api.routers.graph import (
    applications as graph_applications_router,
)
from api.routers.graph import (
    audit_logs as graph_audit_logs_router,
)
from api.routers.graph import (
    auth as graph_auth_router,
)
from api.routers.graph import (
    auth_methods as graph_auth_methods_router,
)
from api.routers.graph import (
    autopilot as graph_autopilot_router,
)
from api.routers.graph import (
    compliance as graph_compliance_router,
)
from api.routers.graph import (
    defender_office as graph_defender_office_router,
)
from api.routers.graph import (
    devices as graph_devices_router,
)
from api.routers.graph import (
    directory as graph_directory_router,
)
from api.routers.graph import (
    enrollment as graph_enrollment_router,
)
from api.routers.graph import (
    files as graph_files_router,
)
from api.routers.graph import (
    groups as graph_groups_router,
)
from api.routers.graph import (
    identity as graph_identity_router,
)
from api.routers.graph import (
    identity_protection as graph_identity_protection_router,
)
from api.routers.graph import (
    licenses as graph_licenses_router,
)
from api.routers.graph import (
    mail as graph_mail_router,
)
from api.routers.graph import (
    organization as graph_organization_router,
)
from api.routers.graph import (
    security as graph_security_router,
)
from api.routers.graph import (
    service_health as graph_service_health_router,
)
from api.routers.graph import (
    service_principals as graph_service_principals_router,
)
from api.routers.graph import (
    teams as graph_teams_router,
)
from api.routers.graph import (
    users as graph_users_router,
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
from api.sentinel_auth import require_arm_api_version
from application.sentinel.commands.edr_bridge import register_sentinel_bridge
from application.splunk.commands.edr_bridge import register_bridge as register_splunk_bridge
from config import API_PREFIX, APP_VERSION, CORS_ORIGINS, PERSIST_PATH
from infrastructure import seed
from utils.entra_token_errors import AADSTS_MISSING_PARAMETER, build_token_error
from utils.es_aggs import ESAggregationError
from utils.es_query import ESQueryError
from utils.es_response import build_es_error_response
from utils.logging import setup_logging
from utils.mde_kql import KqlError
from utils.mde_odata import ODataFilterError
from utils.vendor_errors import (
    build_vendor_error,
    vendor_for_path,
    vendor_mount_for_path,
)

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


# EDR→SIEM bridging (ADR-009). Registered at import rather than in the lifespan
# so the bridge is live for any consumer holding the app object, test clients
# included; subscribe() is idempotent, so a later startup call is harmless.
register_splunk_bridge()
register_sentinel_bridge()

app = FastAPI(
    title="SentinelOne Mock API",
    description="Full-fidelity SentinelOne Management Console API v2.1 mock server",
    version=APP_VERSION,
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
        # kbn-version is Kibana's accepted alternative to kbn-xsrf; without it
        # here a browser client cannot actually send the header the xsrf guard
        # accepts.
        "Authorization", "Content-Type", "Accept", "kbn-xsrf", "kbn-version",
        "x-xdr-auth-id", "x-xdr-nonce", "x-xdr-timestamp",
        "ConsistencyLevel",
    ],
)

# Middleware registration order: last added = outermost wrapper.
# RequestLoggingMiddleware runs first (outermost), then RateLimit, Security, Audit, Proxy innermost.
# Paging runs inside XML rendering, so the sliced entries are what gets rendered.
app.add_middleware(SplunkPagingMiddleware)     # count/offset on Atom collections
app.add_middleware(SplunkOutputModeMiddleware)  # renders Splunk XML around the routers
# Path rewriting must happen before routing, so this is added last (outermost).
app.add_middleware(SplunkNamespaceMiddleware)  # /servicesNS/{owner}/{app} -> /services
app.add_middleware(RecordingProxyMiddleware)  # innermost — added first, runs last
app.add_middleware(FaultInjectionMiddleware)  # fault injection — delay/errors before proxy
app.add_middleware(TenantScopeMiddleware)     # tenant isolation — scope non-admin queries
app.add_middleware(RequestAuditMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(HeadMethodMiddleware)   # HEAD -> GET, body stripped
app.add_middleware(MetricsMiddleware)         # outermost — runs first, captures all timings


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return a vendor-shaped JSON error response for all HTTP errors.

    If the handler already carries a dict detail (e.g. the auth module),
    use it verbatim.  Otherwise synthesise an envelope in the shape of
    whichever vendor owns the request path.

    Headers set on the exception are forwarded. Dropping them silently
    discarded the ``WWW-Authenticate`` challenge Elasticsearch sends on a 401,
    which is the part of the response RFC 7235 clients actually read.
    """
    if isinstance(exc.detail, dict):
        return JSONResponse(
            status_code=exc.status_code, content=exc.detail, headers=exc.headers,
        )

    vendor = vendor_for_path(request.url.path)
    message = exc.detail if isinstance(exc.detail, str) else "Error"
    return JSONResponse(
        status_code=exc.status_code,
        content=build_vendor_error(vendor, exc.status_code, message),
        headers=exc.headers,
    )


#: Paths that mock Entra's token endpoint rather than the API in front of it.
_TOKEN_ENDPOINT_SUFFIX = "/oauth2/v2.0/token"


def _is_token_endpoint(path: str) -> bool:
    """Return whether *path* is one of the mocked Entra token endpoints."""
    return path.endswith(_TOKEN_ENDPOINT_SUFFIX)


@app.exception_handler(JSONDecodeError)
async def json_decode_exception_handler(
    request: Request, exc: JSONDecodeError,
) -> JSONResponse:
    """Answer an unparseable request body the way the mocked vendor would.

    Handlers that read ``await request.json()`` directly — rather than through
    a body model, which pydantic guards — let the decode error escape. That
    surfaced as a bare ``500 Internal Server Error`` in ``text/plain``: not the
    vendor's envelope, not the vendor's status, and not even JSON. Every mocked
    API answers a malformed body with ``400``.
    """
    return JSONResponse(
        status_code=400,
        content=build_vendor_error(
            vendor_for_path(request.url.path),
            400,
            f"Invalid JSON in request body: {exc}",
        ),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError,
) -> JSONResponse:
    """Report request-validation failures the way the mocked vendor would.

    FastAPI's default is ``422`` with a pydantic ``detail`` list. None of the
    mocked APIs use either that status or that body, so a client written
    against the real vendor cannot parse it — the mock would mask an
    integration bug rather than surface it. Errors are flattened into one
    message and returned as a vendor-shaped ``400``.
    """
    parts = []
    for err in exc.errors():
        location = ".".join(str(loc) for loc in err.get("loc", ()) if loc != "body")
        message = err.get("msg", "invalid value")
        parts.append(f"{location}: {message}" if location else message)
    detail = "; ".join(parts) or "Invalid request"

    # A token endpoint is not part of the API it fronts: Entra answers there in
    # OAuth 2.0's flat shape, which is what MSAL parses. Returning the resource
    # API's envelope would hand an OAuth client keys it never reads.
    if _is_token_endpoint(request.url.path):
        return JSONResponse(
            status_code=400,
            content=build_token_error(
                "invalid_request", f"AADSTS900144: {detail}", AADSTS_MISSING_PARAMETER,
            ),
        )

    return JSONResponse(
        status_code=400,
        content=build_vendor_error(vendor_for_path(request.url.path), 400, detail),
    )


@app.exception_handler(ODataFilterError)
async def odata_filter_exception_handler(
    request: Request, exc: ODataFilterError,
) -> JSONResponse:
    """Answer an unparseable ``$filter`` with a vendor-shaped ``400``.

    Defender and Graph reject a malformed or unsupported filter with ``400``.
    Letting the parse error escape would surface as ``500``, which tells a
    client written against the real vendor nothing about what it got wrong.
    """
    return JSONResponse(
        status_code=400,
        content=build_vendor_error(
            vendor_for_path(request.url.path), 400, f"Invalid $filter: {exc}",
        ),
    )


@app.exception_handler(KqlError)
async def kql_exception_handler(
    request: Request, exc: KqlError,
) -> JSONResponse:
    """Answer an unusable hunting query with Defender's ``400``.

    The query was previously accepted and ignored, so a malformed one
    returned canned results rather than telling the caller anything.
    """
    return JSONResponse(
        status_code=400,
        content=build_vendor_error(
            vendor_for_path(request.url.path), 400, str(exc),
        ),
    )


@app.exception_handler(ESAggregationError)
async def es_aggregation_exception_handler(
    _request: Request, exc: ESAggregationError,
) -> JSONResponse:
    """Answer an unusable ``aggs`` block with Elasticsearch's ``400``."""
    return JSONResponse(
        status_code=400,
        content=build_es_error_response(400, "parsing_exception", str(exc)),
    )


@app.exception_handler(ESQueryError)
async def es_query_exception_handler(
    _request: Request, exc: ESQueryError,
) -> JSONResponse:
    """Answer an unparseable search body with Elasticsearch's ``400``.

    Six query types the interpreter does not implement raised a bare
    ``ValueError``, which reached the client as a plain-text ``500`` — an
    Elasticsearch client cannot tell that apart from the cluster falling over.
    """
    return JSONResponse(
        status_code=400,
        content=build_es_error_response(400, "parsing_exception", str(exc)),
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
# ARM management-plane requests must carry ?api-version=, as real Azure demands.
_ARM = [Depends(require_arm_api_version)]

app.include_router(
    sentinel_operations_router.router, prefix=SENTINEL_PREFIX, dependencies=_ARM,
)

# Log Analytics query endpoint — api.loganalytics.io, not ARM: no api-version
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
    app.include_router(
        _sentinel_module.router, prefix=SENTINEL_PREFIX, dependencies=_ARM,
    )

# ── Microsoft Graph API mock endpoints (mounted at /graph) ───────────────────
GRAPH_PREFIX = "/graph"

# OAuth2 token endpoint — no auth required
app.include_router(graph_auth_router.router, prefix=GRAPH_PREFIX)

# Authenticated Graph endpoints — each handler applies its own auth dependency
for _graph_module in [
    graph_organization_router,
    graph_users_router,
    graph_groups_router,
    graph_directory_router,
    graph_auth_methods_router,
    graph_service_principals_router,
    graph_applications_router,
    graph_identity_router,
    graph_identity_protection_router,
    graph_audit_logs_router,
    graph_licenses_router,
    graph_devices_router,
    graph_compliance_router,
    graph_autopilot_router,
    graph_app_protection_router,
    graph_enrollment_router,
    graph_security_router,
    graph_mail_router,
    graph_files_router,
    graph_teams_router,
    graph_defender_office_router,
    graph_service_health_router,
]:
    app.include_router(_graph_module.router, prefix=GRAPH_PREFIX)

# ── Unmatched routes ─────────────────────────────────────────────────────────
#
# The SPA is served here too when a build is present, but the vendor-shaped 404
# must not depend on that: the backend runs without `frontend/dist` in CI and in
# any API-only deployment, and gating this block on the build meant every mocked
# vendor answered FastAPI's `{"detail": "Not Found"}` there instead of its own
# envelope — the exact mismatch this fallback exists to remove.
_DIST = Path(__file__).parent.parent / "frontend" / "dist"
_SPA_AVAILABLE = _DIST.exists()

if _SPA_AVAILABLE:
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

_FALLBACK_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_SAFE_METHODS = ("GET", "HEAD")


def _wants_html(request: Request) -> bool:
    """Return whether this looks like a browser navigation.

    Browsers name ``text/html`` explicitly when navigating; API clients send
    ``application/json`` or ``*/*``. The UI routes under the same top-level
    prefixes as the APIs it mocks — ``/graph/users`` is a page,
    ``/graph/v1.0/users`` is an endpoint — so the path alone cannot say which
    of the two an unmatched request wanted. Only a safe method can be a
    navigation, so a POST carrying a browser's Accept header is still an API
    call and still wants the vendor's error.
    """
    return (
        request.method in _SAFE_METHODS
        and "text/html" in request.headers.get("accept", "")
    )


def _allowed_methods(request: Request) -> list[str]:
    """Return the verbs a registered route accepts for this exact path.

    Claiming every verb on the fallback hides Starlette's own
    method-not-allowed handling, which would turn a wrong verb against a *real*
    endpoint into a 404 — the same misdirection this fallback exists to remove,
    pointed the other way. Routers report only that *some* method would have
    matched, not which, so each verb is offered in turn and the ones that
    resolve are the answer. Only unmatched requests reach here, so this never
    runs on a served route.
    """
    allowed: list[str] = []
    for method in _FALLBACK_METHODS:
        scope = {**request.scope, "method": method}
        for route in app.routes:
            if getattr(route, "path", None) == "/{full_path:path}":
                continue
            try:
                match, _ = route.matches(scope)
            except Exception:  # noqa: BLE001, S112 - unmatchable route is not a match
                continue
            if match is Match.FULL:
                allowed.append(method)
                break

    # RFC 9110 makes HEAD mandatory wherever GET is served, and requires Allow
    # to list it. Starlette answers HEAD from the GET route without registering
    # one, so probing never reports it.
    if "GET" in allowed and "HEAD" not in allowed:
        allowed.append("HEAD")
    return allowed


@app.api_route("/{full_path:path}", methods=_FALLBACK_METHODS, include_in_schema=False)
def unmatched_route(request: Request, full_path: str = "") -> Response:
    """Serve the SPA, or a vendor-shaped error for unmatched API routes.

    Serving index.html for everything meant a mistyped endpoint answered
    ``200 text/html`` — or ``405``, for anything but GET, because only GET
    reached this route. A client written against the real vendor got neither
    the status nor the body it parses, turning a typo into a puzzle. Every
    mocked vendor answers an unknown path with ``404``.
    """
    path = "/" + full_path
    vendor = vendor_mount_for_path(path)

    # The path exists — the verb is what is wrong. That is a 405 for everyone,
    # including the SPA's own routes, and it carries the Allow header RFC 7231
    # requires so a client can correct itself.
    allowed = _allowed_methods(request)
    if allowed:
        return JSONResponse(
            status_code=405,
            content=build_vendor_error(
                vendor or "s1", 405, f"Method {request.method} not allowed",
            ),
            headers={"Allow": ", ".join(allowed)},
        )

    if _SPA_AVAILABLE and _wants_html(request):
        return FileResponse(_DIST / "index.html")

    if vendor is not None:
        return JSONResponse(
            status_code=404,
            content=build_vendor_error(
                vendor, 404, f"Resource not found: {request.method} {path}",
            ),
        )

    if _SPA_AVAILABLE and request.method in _SAFE_METHODS:
        return FileResponse(_DIST / "index.html")

    return JSONResponse(
        status_code=404,
        content=build_vendor_error("s1", 404, f"Resource not found: {path}"),
    )


def _cli() -> None:
    """CLI entrypoint for ``mockdr`` command."""
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)  # nosec B104
