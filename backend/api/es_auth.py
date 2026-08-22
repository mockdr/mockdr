"""FastAPI dependencies for Elastic Security authentication and RBAC.

Elastic Security supports two authentication mechanisms:

* **Basic Auth** — ``Authorization: Basic base64(user:pass)``
* **API Key Auth** — ``Authorization: ApiKey base64(id:key)``

Three predefined roles:

* **admin** — full read/write access.
* **analyst** — read access everywhere; write access to detections, cases,
  and response actions.
* **viewer** — read-only access.  All mutations return 403.

Kibana also requires a ``kbn-xsrf`` header on all non-GET requests.
"""
from __future__ import annotations

import base64
import hmac
import os

from fastapi import Depends, Header, HTTPException, Request

from repository.store import store
from utils.es_response import (
    ES_WWW_AUTHENTICATE,
    build_es_auth_error,
    build_es_error_response,
    build_kbn_error_response,
    build_kibana_error,
)


def _auth_error(request: Request | None, status: int, es_type: str, message: str) -> dict:
    """Build an error body in the envelope the requested product uses.

    These dependencies guard both mounts, but Elasticsearch and Kibana do not
    share an error envelope — Kibana serves Boom payloads — so the body has to
    follow the path the caller actually hit.

    Args:
        request:  Incoming request, used only to tell the two mounts apart.
        status:   HTTP status code.
        es_type:  Elasticsearch exception type, ignored for Kibana.
        message:  Human-readable error description.

    Returns:
        Error body for whichever product owns the path.
    """
    if request is not None and request.url.path.startswith("/kibana"):
        return build_kibana_error(request.url.path, status, message)
    if es_type == "security_exception":
        return build_es_auth_error(status, message)
    return build_es_error_response(status, es_type, message)


def _auth_headers(request: Request | None, status: int) -> dict[str, str] | None:
    """Return the challenge headers Elasticsearch sends alongside a 401.

    Elasticsearch emits ``WWW-Authenticate`` as a real response header as well
    as inside the error body, and a client that follows RFC 7235 looks at the
    header, not the JSON.  Kibana does not do this, so the mount decides.
    """
    if status != 401 or (request is not None and request.url.path.startswith("/kibana")):
        return None
    return {"WWW-Authenticate": ", ".join(ES_WWW_AUTHENTICATE)}

# ── User credentials (read from env vars with mock defaults) ──────────────────

_ES_ADMIN_PASS = os.getenv("ES_ADMIN_PASSWORD", "mock-elastic-password")
_ES_ANALYST_PASS = os.getenv("ES_ANALYST_PASSWORD", "mock-analyst-password")
_ES_VIEWER_PASS = os.getenv("ES_VIEWER_PASSWORD", "mock-viewer-password")

_USERS: dict[str, dict[str, str]] = {
    "elastic": {"password": _ES_ADMIN_PASS, "role": "admin"},
    "analyst": {"password": _ES_ANALYST_PASS, "role": "analyst"},
    "viewer": {"password": _ES_VIEWER_PASS, "role": "viewer"},
}

_WRITE_ROLES: frozenset[str] = frozenset({"admin", "analyst"})


# ── Internal helpers ──────────────────────────────────────────────────────────

def _decode_basic(header_value: str) -> dict | None:
    """Decode a Basic auth header and validate credentials.

    Args:
        header_value: The raw ``Authorization`` header value after ``Basic ``.

    Returns:
        Dict with ``user`` and ``role`` if valid, or ``None``.
    """
    try:
        decoded = base64.b64decode(header_value).decode("utf-8")
    except Exception:
        return None

    if ":" not in decoded:
        return None

    username, password = decoded.split(":", 1)
    user = _USERS.get(username)
    if user is None or not hmac.compare_digest(user["password"], password):
        return None

    return {"user": username, "role": user["role"]}


def _decode_api_key(header_value: str) -> dict | None:
    """Decode an ApiKey auth header and validate against the store.

    Args:
        header_value: The raw ``Authorization`` header value after ``ApiKey ``.

    Returns:
        Dict with ``user`` and ``role`` if valid, or ``None``.
    """
    try:
        decoded = base64.b64decode(header_value).decode("utf-8")
    except Exception:
        return None

    if ":" not in decoded:
        return None

    key_id, api_key = decoded.split(":", 1)
    record = store.get("es_api_keys", key_id)
    if record is None or not hmac.compare_digest(record.get("api_key", ""), api_key):
        return None

    return {"user": key_id, "role": record.get("role", "viewer")}


# ── Public dependencies ──────────────────────────────────────────────────────

async def optional_es_auth(request: Request) -> dict | None:
    """Return the caller's context if they authenticated, else ``None``.

    For routes Kibana serves to anyone but answers more fully to a known
    user. ``/api/status`` is the one that matters: unauthenticated it is
    just ``{"status": {"overall": {"level": ...}}}``, authenticated it carries
    name, uuid, version and metrics. Serving the full document to everyone
    told an anonymous client things Kibana would not.
    """
    authorization = request.headers.get("authorization") or ""
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() == "basic":
        return _decode_basic(value)
    if scheme.lower() == "apikey":
        return _decode_api_key(value)
    return None


async def require_es_auth(
    request: Request,
    authorization: str = Header(None),
) -> dict:
    """Validate Elastic Security authentication and return the user context.

    Supports both Basic and ApiKey authentication schemes.

    Args:
        request:       Incoming request, used to pick the error envelope.
        authorization: Raw ``Authorization`` header value.

    Returns:
        Dict with ``user`` and ``role`` keys.

    Raises:
        HTTPException: 401 if the credentials are missing, malformed, or invalid.
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=_auth_error(
                request, 401, "security_exception",
                f"missing authentication credentials for REST request [{request.url.path}]",
            ),
            headers=_auth_headers(request, 401),
        )

    lower = authorization.lower()

    if lower.startswith("basic "):
        result = _decode_basic(authorization[6:])
    elif lower.startswith("apikey "):
        result = _decode_api_key(authorization[7:])
    elif lower.startswith("bearer "):
        token_value = authorization[7:]
        # Bearer tokens must use full id:key format for validation
        if ":" not in token_value:
            result = None
        else:
            key_id, api_key = token_value.split(":", 1)
            record = store.get("es_api_keys", key_id)
            if record is not None and hmac.compare_digest(record.get("api_key", ""), api_key):
                result = {"user": record.get("name", key_id), "role": record.get("role", "viewer")}
            else:
                result = None
    else:
        result = None

    if result is None:
        raise HTTPException(
            status_code=401,
            detail=_auth_error(
                request, 401, "security_exception",
                f"unable to authenticate user for REST request [{request.url.path}]",
            ),
            headers=_auth_headers(request, 401),
        )

    return result


async def require_es_write(
    request: Request,
    current: dict = Depends(require_es_auth),
) -> dict:
    """Require admin or analyst role for write operations.

    Args:
        request: Incoming request, used to pick the error envelope.
        current: Injected by ``require_es_auth``.

    Returns:
        The authenticated user context.

    Raises:
        HTTPException: 403 if the user role is not permitted to write.
    """
    if current.get("role") not in _WRITE_ROLES:
        user = current.get("user", "")
        raise HTTPException(
            status_code=403,
            detail=_auth_error(
                request, 403, "security_exception",
                f"action [write] is unauthorized for user [{user}]",
            ),
        )
    return current


async def require_kbn_xsrf(request: Request) -> None:
    """Validate the ``kbn-xsrf`` header on non-GET Kibana requests.

    Kibana requires this header to prevent CSRF attacks. Any truthy value is
    accepted, and ``kbn-version`` satisfies the check on its own — Kibana's own
    guard passes when *either* header is present, which is how its browser
    client gets through without sending ``kbn-xsrf``.

    Args:
        request: The incoming FastAPI request.

    Raises:
        HTTPException: 400 if neither header is present on a non-GET request.
    """
    if request.method.upper() in ("GET", "HEAD", "OPTIONS"):
        return

    xsrf = request.headers.get("kbn-xsrf") or request.headers.get("kbn-version")
    if not xsrf:
        # Always Kibana's Boom envelope, never the Security Solution one.
        # The xsrf check is a platform pre-handler that fires before the
        # request is routed, so it has no idea which plugin owns the path —
        # picking the envelope by path here reported `{status_code}` on
        # detection-engine routes where Kibana 8.15 sends `{statusCode, error}`.
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(
                400, "Request must contain a kbn-xsrf header.",
            ),
        )
