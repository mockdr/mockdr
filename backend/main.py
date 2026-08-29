import re
from collections.abc import AsyncGenerator, Mapping
from contextlib import asynccontextmanager
from functools import lru_cache
from json import JSONDecodeError

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.routing import Match
from starlette.types import Scope

from api import spa
from api.auth import require_admin, require_auth
from api.documented_body import require_documented_body
from api.middleware.audit import RequestAuditMiddleware
from api.middleware.body_limit import BodyLimitMiddleware
from api.middleware.compression import CompressionMiddleware
from api.middleware.elastic_headers import ElasticHeadersMiddleware
from api.middleware.elastic_shaping import ElasticShapingMiddleware
from api.middleware.fault_injection import FaultInjectionMiddleware
from api.middleware.head_method import ES_HEAD_PATHS, HeadMethodMiddleware
from api.middleware.json_charset import JsonCharsetMiddleware
from api.middleware.metrics import MetricsMiddleware
from api.middleware.odata_properties import ODataPropertyMiddleware
from api.middleware.proxy import RecordingProxyMiddleware
from api.middleware.rate_limit import RateLimitMiddleware
from api.middleware.request_logging import RequestLoggingMiddleware
from api.middleware.security_headers import SecurityHeadersMiddleware
from api.middleware.splunk_field_filter import SplunkFieldFilterMiddleware
from api.middleware.splunk_headers import SplunkHeadersMiddleware
from api.middleware.splunk_namespace import SplunkNamespaceMiddleware
from api.middleware.splunk_output_mode import SplunkOutputModeMiddleware
from api.middleware.splunk_paging import SplunkPagingMiddleware
from api.middleware.splunk_search import SplunkSearchMiddleware
from api.middleware.splunk_sort import SplunkSortMiddleware
from api.middleware.tenant_scope import TenantScopeMiddleware
from api.middleware.token_cache import TokenCacheMiddleware
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
    cs_iocs as cs_iocs_router,
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
    es_alerting as es_alerting_router,
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
    es_platform as es_platform_router,
)
from api.routers import (
    es_rules as es_rules_router,
)
from api.routers import (
    es_search as es_search_router,
)
from api.routers import (
    es_security_extras as es_security_extras_router,
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
from api.routers.es_search import CatSortError
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
    splunk_catalog as splunk_catalog_router,
)
from api.routers.splunk import (
    splunk_catalogs as splunk_catalogs_router,
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
from application.es_search.queries import (
    SeqNoWithoutTermError,
    VersionConflictError,
    es_index_uuid,
)
from application.sentinel.commands.edr_bridge import register_sentinel_bridge
from application.splunk.commands.edr_bridge import register_bridge as register_splunk_bridge
from config import API_PREFIX, APP_VERSION, CORS_ORIGINS, PERSIST_PATH
from infrastructure import seed
from utils.cs_fql import FqlError
from utils.entra_token_errors import AADSTS_MISSING_PARAMETER, build_token_error
from utils.es_aggs import ESAggregationError
from utils.es_query import ESQueryError
from utils.es_response import (
    ES_WWW_AUTHENTICATE,
    build_es_error_response,
    build_es_index_not_found,
    build_kbn_error_response,
)
from utils.logging import setup_logging
from utils.mde_kql import KqlError
from utils.mde_odata import ODataFilterError
from utils.vendor_errors import (
    build_vendor_error,
    vendor_for_path,
    vendor_mount_for_path,
)
from utils.xdr_filters import XdrFilterError

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
    title="mockdr",
    description=(
        "Multi-EDR mock server: SentinelOne, CrowdStrike Falcon, Defender for Endpoint, "
        "Microsoft Graph, Microsoft Sentinel, Cortex XDR, Splunk and Elastic/Kibana APIs, "
        "measured against the real products and their public references."
    ),
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
# Searching runs innermost of the four, so what is ordered, narrowed, sliced
# and counted is what the search selected.
app.add_middleware(SplunkSearchMiddleware)     # search= on Atom collections
app.add_middleware(SplunkSortMiddleware)       # sort_key/sort_dir, name asc by default
app.add_middleware(SplunkFieldFilterMiddleware)  # f= on Atom entry content
app.add_middleware(SplunkPagingMiddleware)     # count/offset on Atom collections
app.add_middleware(SplunkOutputModeMiddleware)  # renders Splunk XML around the routers
# Outside the renderer, so it has the last word: the renderer writes its own
# content type for the JSON form and would overwrite a charset set beneath it.
app.add_middleware(JsonCharsetMiddleware)      # each product names the charset its own way
app.add_middleware(TokenCacheMiddleware)       # RFC 6749 §5.1 — a token answer is never cached
app.add_middleware(ODataPropertyMiddleware)    # a $select/$filter/$orderby naming nothing is a 400
app.add_middleware(ElasticShapingMiddleware)   # filter_path, pretty, X-Opaque-Id
app.add_middleware(ElasticHeadersMiddleware)   # the header every Elasticsearch client checks for
app.add_middleware(SplunkHeadersMiddleware)    # Server/Vary/caching, and 304 on a fresh read
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
# Compression sits outside everything that rewrites a body, and outside the
# Splunk headers so their ETag is a validator for the entity rather than for
# one of its encodings — which is what makes it stable across them.
app.add_middleware(CompressionMiddleware)  # each product's own gzip policy
app.add_middleware(BodyLimitMiddleware)    # outermost: 413 before any body is read
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
        return _with_repeated_challenges(JSONResponse(
            status_code=exc.status_code, content=exc.detail, headers=exc.headers,
        ), exc.headers)

    vendor = vendor_for_path(request.url.path)
    message = exc.detail if isinstance(exc.detail, str) else "Error"
    return _with_repeated_challenges(JSONResponse(
        status_code=exc.status_code,
        content=build_vendor_error(vendor, exc.status_code, message),
        headers=exc.headers,
    ), exc.headers)


def _with_repeated_challenges(
    response: JSONResponse, headers: Mapping[str, str] | None,
) -> JSONResponse:
    """Send each ``WWW-Authenticate`` scheme as its own header.

    Elasticsearch offers two challenges on a 401 and sends two headers.
    Folding them into one comma-separated value is legal for most headers and
    ambiguous for this one, whose first challenge already contains a comma:
    `Basic realm="security", charset="UTF-8", ApiKey` cannot be split back
    into the two schemes it came from.
    """
    combined = (headers or {}).get("WWW-Authenticate")
    if not combined or "ApiKey" not in combined:
        return response
    del response.headers["WWW-Authenticate"]
    for challenge in ES_WWW_AUTHENTICATE:
        response.raw_headers.append(
            (b"www-authenticate", challenge.encode("latin-1")))
    return response


#: The splunkd paths that answer 405 rather than the EAI collections' 400.
_SPLUNK_SEARCH_405 = re.compile(r"/splunk/services/search/")
_SPLUNK_KVSTORE_405 = re.compile(r"/storage/collections/data/[^/]+/batch_")
#: The job collections, whose DELETE is worded differently from the rest of
#: the search endpoints', and typeahead, whose is different again.
#: Where the search service says `Method Not Allowed` rather than `The method
#: is not allowed.`: the job collections and everything addressed through a
#: job — `{sid}` itself and each of its sub-resources.  `jobs/export` is not a
#: job, and answers with the other wording, as `parser` and `timeparser` do.
#: Measured verb by verb on 10.4.2 against a job that exists.
_SPLUNK_JOB_COLLECTION = re.compile(
    r"/splunk/services/search/(v2/)?jobs(?:/?$|/(?!export(?:/|$)))",
)

#: The two job endpoints that resolve the sid *before* they judge the verb:
#: the job itself and its `control`.  Both take a write, so the handler runs
#: and looks the job up; the read-only sub-resources (`results`, `events`,
#: `summary`, `timeline`, `search.log`, `acl`, `results_preview`) refuse the
#: verb first and answer 405 with `Allow` even for a sid that never existed.
#: Measured one sub-resource at a time — no rule accounts for the split.
_SPLUNK_JOB_SID = re.compile(
    r"/splunk/services/search/(?:v2/)?jobs/(?!export(?:/|$))"
    r"(?P<sid>[^/]+)(?:/control)?/?$",
)

#: The EAI handlers whose `{name}/{action}` paths name a custom action, and
#: the handler name splunkd puts in its refusal.
_SPLUNK_CUSTOM_ACTION = (
    ("/splunk/services/saved/searches/", "savedsearch"),
    ("/splunk/services/data/indexes/", "indexes"),
)
_SPLUNK_TYPEAHEAD = re.compile(r"/splunk/services/search/typeahead")


#: splunkd's answer to a verb a path does not take, which is decided by the
#: *verb* first and the path second (measured across fifteen paths on
#: 10.4.2). mockdr had it the other way round and answered one thing for the
#: search endpoints, another for the KV store's batch paths, and a third for
#: everything else — so `PUT` and `PATCH` on any EAI collection came back as
#: the 400 splunkd keeps for a `POST` with no name to act on.
_SPLUNK_METHOD_NOT_ALLOWED = "Method Not Allowed"


def _es_uri(request: Request, path: str) -> str:
    """The uri Elasticsearch names in a 405, query string and all.

    The cluster echoes what the client sent — `/{index}/_search?size=1`, not
    `/{index}/_search` — and that message is what ends up in a client's log.
    Dropping the query made the mock's 405 name a request nobody had made.
    Measured on 8.15 on two unrelated endpoints.
    """
    inner = path[len("/elastic"):] if path.startswith("/elastic") else path
    query = request.url.query
    return f"{inner}?{query}" if query else inner


def _splunk_wrong_method(
    request: Request, path: str, allowed: tuple[str, ...],
) -> JSONResponse:
    """What splunkd answers when the path exists and the verb does not fit.

    * The search endpoints answer for themselves — see
      `_splunk_search_wrong_method`.
    * `PATCH` is 405 `Method Not Allowed` everywhere else, with no `Allow`.
    * `PUT` is 404 `Requested invalid action 'PUT'.`.
    * A KV store's batch path is 405 *with* an `Allow` naming `POST,PUT`.
    * everything else is the 400 an EAI collection answers a verb it cannot
      route to a named object.
    """
    search = bool(_SPLUNK_SEARCH_405.search(path))
    if search:
        return _splunk_search_wrong_method(request, path, allowed)
    if request.method == "PATCH":
        return JSONResponse(status_code=405, content={
            "messages": [{"type": "ERROR", "text": _SPLUNK_METHOD_NOT_ALLOWED}]})
    if request.method == "PUT":
        return JSONResponse(status_code=404, content={
            "messages": [{"type": "ERROR", "text": "Requested invalid action 'PUT'."}]})
    invalid_action = _splunk_invalid_custom_action(request, path)
    if invalid_action is not None:
        return invalid_action
    if _SPLUNK_KVSTORE_405.search(path):
        return JSONResponse(
            status_code=405, headers={"Allow": ",".join(allowed)},
            content={"messages": [
                {"type": "ERROR", "text": _SPLUNK_METHOD_NOT_ALLOWED}]},
        )
    return JSONResponse(
        status_code=400,
        content={"messages": [{"type": "ERROR", "text":
            f'Cannot perform action "{request.method}" without a target name to act on.'}]},
    )



def _splunk_invalid_custom_action(
    request: Request, path: str,
) -> JSONResponse | None:
    """What splunkd answers when the last segment is not an action it knows.

    An EAI handler maps the verb to an *eai action* — `DELETE` is `remove` —
    and then looks for the trailing segment among the custom actions that
    action allows.  `DELETE /saved/searches/{name}/dispatch` is a 404 naming
    all three, not the 400 an unnamed target gets: the path names a target
    perfectly well, and mockdr's `without a target name to act on` read as
    nonsense to anyone who looked at it.  Measured on 10.4.2, on names that
    exist and names that do not — the object is never resolved this far.
    """
    if request.method != "DELETE":
        return None
    for prefix, handler in _SPLUNK_CUSTOM_ACTION:
        if not path.startswith(prefix):
            continue
        rest = path[len(prefix):].strip("/").split("/")
        if len(rest) != 2:
            continue
        return JSONResponse(status_code=404, content={"messages": [{
            "type": "ERROR",
            "text": f"Invalid custom action for this internal handler "
                    f"(handler: {handler}, custom action: {rest[1]}, "
                    f"eai action: remove).",
        }]})
    return None


def _splunk_search_wrong_method(
    request: Request, path: str, allowed: tuple[str, ...],
) -> JSONResponse:
    """The search endpoints' answer, which is theirs alone.

    `PUT` and `PATCH` are the plain 405 with no `Allow`, wherever they land.
    Any other verb a path does not take is FATAL *with* an `Allow` — and in
    two wordings: the job collections say `Method Not Allowed`, everything
    else `The method is not allowed.`. `typeahead` is outside all of it and
    answers the plain 405 to every wrong verb. Measured path by path on
    10.4.2, because no rule accounts for the split.
    """
    if _SPLUNK_TYPEAHEAD.search(path) or request.method in ("PUT", "PATCH"):
        return JSONResponse(status_code=405, content={
            "messages": [{"type": "ERROR", "text": _SPLUNK_METHOD_NOT_ALLOWED}]})
    # Every other verb reaches the handler, which resolves the sid before it
    # decides anything about the method: `DELETE …/jobs/{unknown}/control` is
    # 404 `Unknown sid.`, not a 405.  `PUT` and `PATCH` above never get that
    # far, which is why the sid check sits here and not at the top.
    named = _SPLUNK_JOB_SID.search(path)
    if named is not None:
        from repository.splunk.search_job_repo import search_job_repo
        if search_job_repo.get(named.group("sid")) is None:
            return JSONResponse(status_code=404, content={
                "messages": [{"type": "FATAL", "text": "Unknown sid."}]})
    text = (
        _SPLUNK_METHOD_NOT_ALLOWED if _SPLUNK_JOB_COLLECTION.search(path)
        else "The method is not allowed."
    )
    return JSONResponse(
        status_code=405, headers={"Allow": ",".join(allowed)},
        content={"messages": [{"type": "FATAL", "text": text}]},
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
    if vendor_for_path(request.url.path) == "elasticsearch":
        # A body of the wrong JSON type is reported as what the parser saw,
        # not as pydantic's wording (measured on 8.15).
        wrong = next((e for e in exc.errors() if e.get("type") == "dict_type"), None)
        if wrong is not None:
            found = _JSON_TOKEN_NAMES.get(type(wrong.get("input")), "VALUE_STRING")
            content = build_es_error_response(
                400, "parsing_exception", f"Expected [START_OBJECT] but found [{found}]",
            )
            for entry in (content["error"], *content["error"].get("root_cause", [])):
                entry["line"], entry["col"] = 1, 1
            return JSONResponse(status_code=400, content=content)

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


@app.exception_handler(FqlError)
async def fql_exception_handler(request: Request, exc: FqlError) -> JSONResponse:
    """Answer a filter that is not FQL with the 400 the Falcon API sends.

    mockdr used to ignore it and return every record — so a client that
    mistyped its filter, or wrote one for a different API, was handed the
    whole collection and read it as the matches.
    """
    return JSONResponse(
        status_code=400,
        content=build_vendor_error(
            vendor_for_path(request.url.path), 400, str(exc),
        ),
    )


@app.exception_handler(XdrFilterError)
async def xdr_filter_exception_handler(
    request: Request, exc: XdrFilterError,
) -> JSONResponse:
    """Answer an unsupported XDR filter with a 400, as Cortex XDR does."""
    return JSONResponse(
        status_code=400,
        content=build_vendor_error(
            vendor_for_path(request.url.path), 400, str(exc),
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
    """Answer an unusable ``aggs`` block with Elasticsearch's ``400``.

    An unknown aggregation *type* carries the same position and cause an
    unknown query type does (measured on 8.15).
    """
    if exc.es_type == "x_content_parse_exception":
        # This one carries its position inside the reason text and no line or
        # col members. It points at the field *name* where the others point
        # at the value the parser was reading — except when the complaint is
        # about the value itself, which is where the parser then stands
        # (measured on 8.15).
        raw = await _request.body()
        line, col = (
            _body_position(raw, exc.clause or "") if exc.value_position
            else _key_position(raw, exc.clause or "")
        )
        content = build_es_error_response(400, exc.es_type, f"[{line}:{col}] {exc}")
        if exc.caused_by is not None:
            content["error"]["caused_by"] = dict(exc.caused_by)
        return JSONResponse(status_code=400, content=content)
    content = build_es_error_response(400, exc.es_type, str(exc))
    if exc.clause is not None:
        line, col = _body_position(await _request.body(), exc.clause, at_end=exc.at_end)
        for entry in (content["error"], *content["error"].get("root_cause", [])):
            entry["line"] = line
            entry["col"] = col
        if exc.named_object:
            content["error"]["caused_by"] = {
                "type": "named_object_not_found_exception",
                "reason": f"[{line}:{col}] unknown field [{exc.clause}]",
            }
    return JSONResponse(status_code=400, content=content)


_JSON_TOKEN_NAMES = {dict: "START_OBJECT", list: "START_ARRAY", str: "VALUE_STRING",
                     bool: "VALUE_BOOLEAN", int: "VALUE_NUMBER",
                     float: "VALUE_NUMBER", type(None): "VALUE_NULL"}


def _key_position(body: bytes, clause: str) -> tuple[int, int]:
    """Line and column (1-based) of the field name itself."""
    text = body.decode("utf-8", errors="replace")
    key = text.find(f'"{clause}"')
    if key < 0:
        return 1, 1
    line = text.count("\n", 0, key) + 1
    column = key - (text.rfind("\n", 0, key) + 1) + 1
    return line, column


def _body_position(body: bytes, clause: str, *, at_end: bool = False) -> tuple[int, int]:
    """Line and column (1-based) where Elasticsearch would report the clause.

    Not where the key starts: where the parser *stood* when it failed, which
    is the first character of the clause's value. For
    ``{"query":{"not_a_real_clause":{}}}`` that is the ``{`` at column 31,
    and that is what Elasticsearch 8.15 reports.

    ``at_end`` moves to the first ``}`` at or after that, which is where an
    *empty* clause body closes — `"query":{}` and `"must":[{}]` alike.
    """
    text = body.decode("utf-8", errors="replace")
    # A dotted path finds each name after the one before it: `terms.size`
    # points at the `size` *inside* the aggregation, not at the `size` a
    # search body carries at the top.
    names = clause.split(".")
    key, offset = -1, 0
    for name in names:
        key = text.find(f'"{name}"', offset)
        if key < 0:
            return 1, 1
        offset = key + len(name) + 2
    if key < 0:
        return 1, 1
    offset = key + len(names[-1]) + 2
    while offset < len(text) and text[offset] in ": \t\r\n":
        offset += 1
    if at_end:
        closing = text.find("}", offset)
        offset = closing if closing >= 0 else offset
    return text.count("\n", 0, offset) + 1, offset - text.rfind("\n", 0, offset)


def _searched_index(request: Request) -> str:
    """The index a search was addressed to, read from its path."""
    parts = [p for p in request.url.path.split("/") if p]
    if len(parts) >= 2 and parts[0] == "elastic" and not parts[1].startswith("_"):
        return parts[1]
    return "mockdr"


@app.exception_handler(VersionConflictError)
async def version_conflict_handler(
    request: Request, exc: VersionConflictError,
) -> JSONResponse:
    """A write whose precondition no longer holds is a 409, not a silent 200."""
    detail = {
        "type": "version_conflict_engine_exception", "reason": exc.reason,
        "index_uuid": es_index_uuid(exc.index), "shard": "0", "index": exc.index,
    }
    return JSONResponse(status_code=409, content={
        "error": {"root_cause": [dict(detail)], **detail}, "status": 409,
    })


@app.exception_handler(SeqNoWithoutTermError)
async def seq_no_without_term_handler(
    request: Request, exc: SeqNoWithoutTermError,
) -> JSONResponse:
    """`if_seq_no` without `if_primary_term` is a validation failure."""
    return JSONResponse(status_code=400, content=build_es_error_response(
        400, "action_request_validation_exception", str(exc),
    ))


@app.exception_handler(CatSortError)
async def cat_sort_error_handler(request: Request, exc: CatSortError) -> JSONResponse:
    """`_cat?s=…` naming a column no row carries is an illegal argument."""
    return JSONResponse(status_code=400, content=build_es_error_response(
        400, "illegal_argument_exception", str(exc),
    ))


@app.exception_handler(ESQueryError)
async def es_query_exception_handler(
    _request: Request, exc: ESQueryError,
) -> JSONResponse:
    """Answer an unparseable search body with Elasticsearch's ``400``.

    Six query types the interpreter does not implement raised a bare
    ``ValueError``, which reached the client as a plain-text ``500`` — an
    Elasticsearch client cannot tell that apart from the cluster falling over.
    """
    if exc.shard_failure:
        # What a shard raises comes back wrapped: one root cause and one
        # failed shard per shard (mockdr has one), with `phase` and `grouped`
        # naming where it happened. An argument error also repeats itself down
        # a two-level caused_by; a date-math parse error does not — both
        # measured against 8.15.
        index = _searched_index(_request)
        cause = {"type": exc.es_type, "reason": str(exc)}
        if exc.es_type == "query_shard_exception":
            # What the *shard* raises names the shard's index; what the
            # coordinating node raises does not (both measured on 8.15).
            cause = {**cause, "index_uuid": es_index_uuid(index), "index": index}
        error: dict = {
            "root_cause": [dict(cause)], "type": "search_phase_execution_exception",
            "reason": "all shards failed", "phase": "query", "grouped": True,
            # The failed shard names the index the search was against, which
            # is the one in the path: a client reading the failure to find
            # out *where* it happened was told "mockdr" every time.
            "failed_shards": [{"shard": 0, "index": index,
                               "node": "mockdr-node-1", "reason": dict(cause)}],
        }
        if exc.es_type == "illegal_argument_exception":
            error["caused_by"] = {**cause, "caused_by": dict(cause)}
        return JSONResponse(status_code=400, content={"error": error, "status": 400})
    content = build_es_error_response(400, exc.es_type, str(exc), exc.detail)
    if exc.caused_by is not None:
        content["error"]["caused_by"] = dict(exc.caused_by)
    if exc.clause is not None:
        # Elasticsearch reports where in the body the unknown clause sits and
        # wraps the cause. The position is found in the bytes the client
        # actually sent, not in a re-serialisation of them, so it points at
        # what they will see when they look.
        # GET _search?source= carries the body in the query string; the
        # position is found in whichever the client actually sent.
        # A multi-search counts the position inside the search that failed,
        # not inside the whole ndjson payload; the error carries that text.
        text = (
            exc.body.encode()
            or await _request.body()
            or _request.query_params.get("source", "").encode()
        )
        line, col = _body_position(text, exc.clause, at_end=exc.at_end)
        if exc.position_format:
            # The reason ends with the position rather than opening on it.
            for entry in (content["error"], *content["error"].get("root_cause", [])):
                entry["reason"] = entry["reason"].format(position=f"[{line}:{col}]")
        elif exc.position_in_message:
            # `[line:col] …` in front of the reason, and on the end of the
            # cause, rather than as two fields of its own.
            for entry in (content["error"], *content["error"].get("root_cause", [])):
                entry["reason"] = f"[{line}:{col}] {entry['reason']}"
            if exc.caused_by is not None:
                content["error"]["caused_by"]["reason"] += f" [{line}:{col}]"
        else:
            for entry in (content["error"], *content["error"].get("root_cause", [])):
                entry["line"] = line
                entry["col"] = col
        if exc.named_object:
            content["error"]["caused_by"] = {
                "type": "named_object_not_found_exception",
                "reason": f"[{line}:{col}] unknown field [{exc.clause}]",
            }
    return JSONResponse(status_code=400, content=content)


# ── Metrics (no auth, no prefix — mounted at /metrics) ───────────────────────
app.include_router(metrics_router.router)

# ── Public (no auth) ──────────────────────────────────────────────────────────
app.include_router(docs.router, prefix=API_PREFIX)
app.include_router(system.public_router, prefix=API_PREFIX)
app.include_router(webhook_sink.public_router, prefix=API_PREFIX)

# ── Authenticated (read-only is fine) ─────────────────────────────────────────
# `require_documented_body` sits beside the auth check on every SentinelOne
# router: a write body carrying none of the members the vendor's swagger
# documents for that route is refused before the handler defaults it into
# something it was never sent.
_AUTH = [Depends(require_auth), Depends(require_documented_body)]

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
# The same body guard as the SentinelOne mount: gofalcon says which members
# a Falcon write body must carry, and six routes answered 200 without them.
for _cs_module in [
    cs_hosts_router,
    cs_detections_router,
    cs_iocs_router,
    cs_host_groups_router,
    cs_users_router,
    cs_processes_router,
    cs_quarantine_router,
    cs_cases_router,
    cs_discover_router,
]:
    app.include_router(_cs_module.router, prefix=CS_PREFIX,
                       dependencies=[Depends(require_documented_body)])

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
    es_alerting_router,
    es_endpoints_router,
    es_platform_router,
    es_security_extras_router,
    es_rules_router,
    es_alerts_router,
    es_cases_router,
    es_exception_lists_router,
]:
    app.include_router(_es_module.router, prefix=KBN_PREFIX)

# ── Cortex XDR mock endpoints (mounted at /xdr/public_api/v1) ────────────────
XDR_PREFIX = "/xdr/public_api/v1"

# All XDR endpoints — each handler applies its own auth dependency via require_xdr_auth
_XDR_MODULES = [
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
]

for _xdr_module in _XDR_MODULES:
    app.include_router(_xdr_module.router, prefix=XDR_PREFIX,
                       dependencies=[Depends(require_documented_body)])

# Cortex paths are written both ways in the wild — the community
# transcription of the reference spells them without a trailing slash, the
# connector code with one — and mockdr served forty-five of its fifty-one
# with the slash and six without, refusing the other spelling with a 404. A
# client keeping to either convention therefore hit a wall on some routes.
# Each route answers to both now; the alias stays out of the schema so the
# published surface still names one path per route.
for _xdr_module in _XDR_MODULES:
    for _route in list(_xdr_module.router.routes):
        if not isinstance(_route, APIRoute):
            continue
        _twin = _route.path[:-1] if _route.path.endswith("/") else _route.path + "/"
        if any(isinstance(r, APIRoute) and r.path == _twin
               for r in _xdr_module.router.routes):
            continue
        app.router.add_api_route(
            XDR_PREFIX + _twin, _route.endpoint,
            methods=sorted(_route.methods or {"POST"}),
            dependencies=[Depends(require_documented_body)],
            include_in_schema=False, name=f"{_route.name}_slash",
        )

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
    splunk_catalog_router,
    splunk_catalogs_router,
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
# The SPA decision lives in api/spa.py, so the routes that share a path with
# a UI route reach the same answer this fallback does.
_DIST = spa.DIST
_SPA_AVAILABLE = spa.SPA_AVAILABLE

if _SPA_AVAILABLE:
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

_FALLBACK_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_SAFE_METHODS = spa.SAFE_METHODS


@lru_cache(maxsize=1024)
def _path_is_registered(path: str) -> bool:
    """Whether any route owns this path, whatever verb it takes.

    The route table is fixed once the app is built, so the answer for a path
    is too — and a client looping on a typo, or a probe walking the surface,
    asks the same question thousands of times. ``PARTIAL`` is the marker: a
    path that exists under another verb reports it, a path nothing owns
    reports nothing.
    """
    scope: Scope = {
        "type": "http", "method": "GET", "path": path, "root_path": "",
        "headers": [], "query_string": b"", "app": app,
    }
    for route in app.routes:
        if getattr(route, "path", None) == "/{full_path:path}":
            continue
        try:
            match, _ = route.matches(scope)
        except Exception:  # noqa: BLE001, S112 - an unmatchable route is not a match
            continue
        if match is not Match.NONE:
            return True
    return False


def _allowed_methods(request: Request) -> tuple[str, ...]:
    """Return the verbs a registered route accepts for this exact path.

    Claiming every verb on the fallback hides Starlette's own
    method-not-allowed handling, which would turn a wrong verb against a *real*
    endpoint into a 404 — the same misdirection this fallback exists to remove,
    pointed the other way. Routers report only that *some* method would have
    matched, not which, so each verb is offered in turn and the ones that
    resolve are the answer. Only unmatched requests reach here, so this never
    runs on a served route.
    """
    return _allowed_methods_for(request.scope.get("path", ""))


@lru_cache(maxsize=1024)
def _allowed_methods_for(path: str) -> tuple[str, ...]:
    """The verbs registered for ``path``; cached, because the route table is."""
    # A path no route knows at all — a client's typo, a probe — matches
    # nothing, and there is no verb to offer. Only a path that exists under
    # another verb reports PARTIAL, and only that case pays the seven-verb
    # probe below.
    if not _path_is_registered(path):
        return ()

    allowed: list[str] = []
    for method in _FALLBACK_METHODS:
        scope: Scope = {
            "type": "http", "method": method, "path": path, "root_path": "",
            "headers": [], "query_string": b"", "app": app,
        }
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
    # one, so probing never reports it. Elasticsearch is the exception twice
    # over: it serves HEAD on its existence endpoints alone, and so lists it
    # in `Allow` there alone — `/_cluster/health` answers `Allow: GET`.
    serves_head = not path.startswith("/elastic") or bool(ES_HEAD_PATHS.match(path))
    if "GET" in allowed and "HEAD" not in allowed and serves_head:
        allowed.append("HEAD")
    return tuple(allowed)


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
    if allowed and vendor == "splunk_hec":
        # HEC answers a wrong verb with HTTP 405 and a body that says 404
        # (measured on 10.4.2). Both halves are what a client sees.
        return JSONResponse(
            status_code=405,
            content={"text": "The requested URL was not found on this server.", "code": 404},
        )
    if allowed and vendor == "splunk":
        return _splunk_wrong_method(request, path, allowed)
    if allowed and vendor == "elasticsearch":
        # Elasticsearch's 405 carries a bare string, not the nested error
        # object every other status uses, and it names the verbs the uri does
        # take (measured on 8.15).
        return JSONResponse(status_code=405, content={
            "error": f"Incorrect HTTP method for uri [{_es_uri(request, path)}] "
                     f"and method [{request.method}], "
                     f"allowed: [{', '.join(allowed)}]",
            "status": 405,
            # No space after the comma, which is how the cluster writes it.
        }, headers={"Allow": ",".join(allowed)})
    if allowed and vendor == "kibana":
        # Kibana registers a route per method, so a verb it does not take is
        # simply no route: 404, with the same body it sends for a path that
        # does not exist, and no Allow header (measured on 8.15). A client
        # correcting itself off a 405 would wait for one that never comes.
        return JSONResponse(
            status_code=404, content=build_kbn_error_response(404, "Not Found"),
        )
    if allowed:
        return JSONResponse(
            status_code=405,
            content=build_vendor_error(
                vendor or "s1", 405, f"Method {request.method} not allowed",
            ),
            headers={"Allow": ", ".join(allowed)},
        )

    if _SPA_AVAILABLE and spa.wants_html(request):
        return FileResponse(_DIST / "index.html")

    if vendor is not None:
        # splunkd says only "Not Found" (measured on 10.4.2); the method and
        # path are something mockdr added for its own diagnostics, and a
        # client matching on the text would not find what splunkd sends.
        if vendor == "elasticsearch":
            # Elasticsearch has no "resource not found": a single unknown
            # segment is an index name. One starting with "_" is invalid
            # (400), any other is an index that does not exist (404), and
            # an unknown _cat verb is a 405 whose error is a bare string.
            # All three measured on 8.15.
            inner = path[len("/elastic"):] if path.startswith("/elastic") else path
            segments = [seg for seg in inner.split("/") if seg]
            if segments and segments[0] == "_cat":
                return JSONResponse(status_code=405, content={
                    "error": f"Incorrect HTTP method for uri "
                             f"[{_es_uri(request, path)}] and method "
                             f"[{request.method}], allowed: [POST]",
                    "status": 405,
                })
            if len(segments) == 1:
                name = segments[0]
                if name.startswith("_"):
                    detail = {
                        "type": "invalid_index_name_exception",
                        "reason": f"Invalid index name [{name}], must not start with '_'.",
                        "index_uuid": "_na_", "index": name,
                    }
                    return JSONResponse(status_code=400, content={
                        "error": {"root_cause": [dict(detail)], **detail}, "status": 400,
                    })
                return JSONResponse(status_code=404, content=build_es_index_not_found(name))
        if vendor in ("splunk", "splunk_hec"):
            # Two 404s, measured on 10.4.2: the search service has its own
            # dispatcher and refuses an unknown path under it as FATAL
            # "Unknown endpoint."; everywhere else splunkd says ERROR "Not
            # Found". Neither carries the method or path mockdr used to add.
            if "/services/collector" in path:
                # The collector answers on its own port, and its 404 is the
                # web server's rather than splunkd's REST one: measured on
                # 10.4.2, `{"text": "The requested URL was not found on this
                # server.", "code": 404}` where the management port answers
                # `{"messages": [{"type": "ERROR", "text": "Not Found"}]}`.
                content: dict = {
                    "text": "The requested URL was not found on this server.",
                    "code": 404,
                }
            elif re.search(r"/services/search/jobs/[^/]+/", path):
                # Anything under a job is resolved by sid first; an unknown
                # sid is reported before the sub-resource is looked at.
                content = {"messages": [{"type": "FATAL", "text": "Unknown sid."}]}
            elif "/services/search/" in path:
                content = {"messages": [{"type": "FATAL", "text": "Unknown endpoint."}]}
            else:
                content = build_vendor_error(vendor, 404, "Not Found")
            return JSONResponse(status_code=404, content=content)
        return JSONResponse(
            status_code=404,
            content=build_vendor_error(
                vendor,
                404,
                # Kibana's own wording for anything it cannot route, which is
                # the bare status title and nothing about the request.
                "Not Found" if vendor == "kibana"
                else f"Resource not found: {request.method} {path}",
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
    uvicorn.run(
        "main:app",
        # A mock others reach over the network: bound on purpose, and the
        # marker sits on the argument bandit points at rather than on the
        # call, which it stopped attributing the finding to.
        host="0.0.0.0",  # nosec B104
        port=8001,
        reload=True,
        server_header=False,
    )
