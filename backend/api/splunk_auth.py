"""FastAPI dependencies for Splunk REST API authentication.

Splunk supports three auth schemes:

1. **Basic Auth** (``Authorization: Basic <b64>``).
2. **Bearer Token** (``Authorization: Bearer <session_key>``) — obtained via
   ``POST /services/auth/login``.
3. **HEC Token** (``Authorization: Splunk <hec_token>``) — for HTTP Event
   Collector endpoints only.

Three pre-seeded credentials:
- ``admin`` / ``mockdr-admin`` (role: ``admin``)
- ``analyst`` / ``mockdr-analyst`` (role: ``sc_admin``)
- ``viewer`` / ``mockdr-viewer`` (role: ``user``)
"""
from __future__ import annotations

import base64
import os
import secrets
import time
from typing import cast

from fastapi import Depends, Header, HTTPException, Request

from repository.splunk.hec_token_repo import hec_token_repo
from repository.splunk.splunk_user_repo import splunk_user_repo
from repository.store import store

# ── Session token management ───────────────────────────────────────────────

_SPLUNK_SESSION_COLLECTION = "splunk_sessions"

# Session expiry in seconds (default 8 hours, configurable via env var)
_SESSION_TTL_SECONDS = int(os.environ.get("SPLUNK_SESSION_TTL_SECONDS", str(8 * 3600)))


def create_session(username: str) -> str:
    """Create a new session token for the given user.

    Args:
        username: Authenticated username.

    Returns:
        The generated session key string.
    """
    session_key = secrets.token_hex(32)
    store.save(_SPLUNK_SESSION_COLLECTION, session_key, {
        "username": username,
        "created_at": time.time(),
    })
    return session_key


def _resolve_session(session_key: str) -> str | None:
    """Return the username for a valid session key, or None.

    Checks session age against ``_SESSION_TTL_SECONDS``. Expired sessions
    are deleted and treated as invalid.
    """
    record = store.get(_SPLUNK_SESSION_COLLECTION, session_key)
    if not record:
        return None

    created_at = record.get("created_at")
    if created_at is not None and (time.time() - created_at) > _SESSION_TTL_SECONDS:
        # Session has expired — remove it and reject
        store.delete(_SPLUNK_SESSION_COLLECTION, session_key)
        return None

    return cast(str, record["username"])


# ── Public dependencies ──────────────────────────────────────────────────

async def require_splunk_auth(
    request: Request,
    authorization: str | None = Header(None),
) -> dict:
    """Validate Splunk authentication (Basic or Bearer) and return user info.

    Args:
        request:       The incoming request (used for form-body fallback).
        authorization: The Authorization header value.

    Returns:
        Dict with ``username`` and ``roles`` keys.

    Raises:
        HTTPException: 401 if authentication fails.
    """
    if authorization:
        # Bearer token
        if authorization.startswith("Bearer "):
            token = authorization[7:]
            username = _resolve_session(token)
            if username:
                user = splunk_user_repo.get(username)
                if user:
                    return {"username": user.username, "roles": user.roles}
            raise HTTPException(status_code=401, detail={"messages": [
                {"type": "ERROR", "text": "Invalid or expired session token"},
            ]})

        # Basic auth
        if authorization.startswith("Basic "):
            try:
                decoded = base64.b64decode(authorization[6:]).decode()
                uname, passwd = decoded.split(":", 1)
                user = splunk_user_repo.authenticate(uname, passwd)
                if user:
                    return {"username": user.username, "roles": user.roles}
            except Exception:
                pass
            raise HTTPException(status_code=401, detail={"messages": [
                {"type": "ERROR", "text": "Invalid credentials"},
            ]})

    raise HTTPException(status_code=401, detail={"messages": [
        {"type": "ERROR", "text": "Authentication required"},
    ]})


async def require_splunk_admin(
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Require the ``admin`` role for management operations.

    This dependency should be composed with ``require_splunk_auth`` via
    ``Depends``.

    Args:
        current_user: Injected by ``require_splunk_auth``.

    Returns:
        The authenticated user dict.

    Raises:
        HTTPException: 403 if user lacks admin role.
    """
    if "admin" not in current_user.get("roles", []):
        raise HTTPException(status_code=403, detail={"messages": [
            {"type": "ERROR", "text": "Insufficient privileges"},
        ]})
    return current_user


async def require_hec_auth(
    authorization: str | None = Header(None),
) -> dict:
    """Validate Splunk HEC token authentication.

    HEC uses ``Authorization: Splunk <token-value>`` header.

    Args:
        authorization: The Authorization header value.

    Returns:
        Dict with ``token_name``, ``index``, ``sourcetype`` from the token.

    Raises:
        HTTPException: 401/403 if token is invalid or disabled.
    """
    if not authorization or not authorization.startswith("Splunk "):
        raise HTTPException(status_code=401, detail={"text": "Token required", "code": 2})

    token_value = authorization[7:]
    token = hec_token_repo.get(token_value)
    if not token:
        raise HTTPException(status_code=403, detail={"text": "Invalid token", "code": 4})
    if token.disabled:
        raise HTTPException(status_code=403, detail={"text": "Token disabled", "code": 1})

    return {
        "token_name": token.name,
        "token": token.token,
        "index": token.index,
        "sourcetype": token.sourcetype,
    }
