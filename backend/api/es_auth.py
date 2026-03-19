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
from utils.es_response import build_es_error_response

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

async def require_es_auth(authorization: str = Header(None)) -> dict:
    """Validate Elastic Security authentication and return the user context.

    Supports both Basic and ApiKey authentication schemes.

    Args:
        authorization: Raw ``Authorization`` header value.

    Returns:
        Dict with ``user`` and ``role`` keys.

    Raises:
        HTTPException: 401 if the credentials are missing, malformed, or invalid.
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=build_es_error_response(
                401, "security_exception",
                "missing authentication credentials",
            ),
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
            detail=build_es_error_response(
                401, "security_exception",
                "unable to authenticate user",
            ),
        )

    return result


async def require_es_write(
    current: dict = Depends(require_es_auth),
) -> dict:
    """Require admin or analyst role for write operations.

    Args:
        current: Injected by ``require_es_auth``.

    Returns:
        The authenticated user context.

    Raises:
        HTTPException: 403 if the user role is not permitted to write.
    """
    if current.get("role") not in _WRITE_ROLES:
        raise HTTPException(
            status_code=403,
            detail=build_es_error_response(
                403, "security_exception",
                "action [write] is unauthorized for user [" + current.get("user", "") + "]",
            ),
        )
    return current


async def require_kbn_xsrf(request: Request) -> None:
    """Validate the ``kbn-xsrf`` header on non-GET Kibana requests.

    Kibana requires this header to prevent CSRF attacks. Any truthy value
    is accepted.

    Args:
        request: The incoming FastAPI request.

    Raises:
        HTTPException: 400 if the header is missing on a non-GET request.
    """
    if request.method.upper() in ("GET", "HEAD", "OPTIONS"):
        return

    xsrf = request.headers.get("kbn-xsrf")
    if not xsrf:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(
                400, "bad_request",
                "Request must contain a kbn-xsrf header.",
            ),
        )
