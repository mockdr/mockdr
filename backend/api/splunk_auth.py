"""FastAPI dependencies for Splunk REST API authentication.

Splunk supports these auth schemes:

1. **Basic Auth** (``Authorization: Basic <b64>``).
2. **Session key** (``Authorization: Splunk <session_key>``) — splunkd's own
   scheme, obtained via ``POST /services/auth/login``.
3. **Bearer Token** (``Authorization: Bearer <session_key>``) — the same key in
   the scheme used for JWT authentication tokens.
4. **HEC Token** (``Authorization: Splunk <hec_token>``) — for HTTP Event
   Collector endpoints, which authenticate against their own token store.

Scheme names are matched case-insensitively, as RFC 7235 requires.

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

from fastapi import Depends, Header, HTTPException, Query, Request

from config import SPLUNK_HEC_QUERY_STRING_AUTH
from repository.splunk.hec_token_repo import hec_token_repo
from repository.splunk.splunk_user_repo import splunk_user_repo
from repository.store import store
from utils.splunk.hec_validation import QUERY_STRING_AUTH_DISABLED
from utils.splunk.response import build_splunk_error

# ── Session token management ───────────────────────────────────────────────

_SPLUNK_SESSION_COLLECTION = "splunk_sessions"

#: How long a session key may go unused before splunkd forgets it.
#:
#: server.conf `[general] sessionTimeout`: "The amount of time before a user
#: session times out", default one hour (Splunk 10.4 server.conf.spec) — a
#: timeout of *idle* time, "the maximum idle time in the interaction"
#: (Admin Manual, "Configure user session timeouts"), which every use
#: restarts. The mock expired a key eight hours after login however busy it
#: was, so a SOAR poller that logs in once and polls every minute was
#: refused mid-run where splunkd keeps its session alive, while one that sat
#: idle for seven hours was still let in.
_SESSION_TTL_SECONDS = int(os.environ.get("SPLUNK_SESSION_TTL_SECONDS", "3600"))


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

    A session idle for longer than ``_SESSION_TTL_SECONDS`` is deleted and
    treated as invalid; any other use restarts its idle clock.
    """
    record = store.get(_SPLUNK_SESSION_COLLECTION, session_key)
    if not record:
        return None

    now = time.time()
    if session_expired(record, now):
        store.delete(_SPLUNK_SESSION_COLLECTION, session_key)
        return None
    # A use restarts the idle clock. Written into the live record rather than
    # saved, so a busy poller is not a store write — and a persistence
    # flush — per request; the next save carries it.
    record["last_used"] = now
    return cast(str, record["username"])


def session_expired(record: dict, now: float) -> bool:
    """Whether a session has been idle longer than ``sessionTimeout``."""
    last = record.get("last_used", record.get("created_at"))
    return last is not None and (now - float(last)) > _SESSION_TTL_SECONDS


def reap_sessions(now: float | None = None) -> int:
    """Forget every session idle past its timeout; how many were forgotten."""
    moment = time.time() if now is None else now
    idle = [
        key for key, record in store.get_all_with_keys(_SPLUNK_SESSION_COLLECTION).items()
        if isinstance(record, dict) and session_expired(record, moment)
    ]
    for key in idle:
        store.delete(_SPLUNK_SESSION_COLLECTION, key)
    return len(idle)


# ── Public dependencies ──────────────────────────────────────────────────

#: splunkd answers every authentication failure with this one string,
#: whether credentials were absent, malformed or simply wrong.
_AUTH_FAILED = "call not properly authenticated"

#: splunkd answers a missing or wrong *password* differently from a bad
#: *token*: ERROR "Unauthorized" with a Basic challenge for the former, WARN
#: "call not properly authenticated" and no challenge for the latter. Two
#: failures, two shapes — measured on Splunk 10.4.2.
_UNAUTHORIZED = {"messages": [{"type": "ERROR", "text": "Unauthorized"}]}
_BASIC_CHALLENGE = {"WWW-Authenticate": 'Basic realm="/splunk"'}



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
        # Session key — splunkd's own scheme — or a Bearer JWT.
        if authorization.lower().startswith("splunk "):
            username = _resolve_session(authorization[7:])
            if username:
                user = splunk_user_repo.get(username)
                if user:
                    return {"username": user.username, "roles": user.roles}
            raise HTTPException(status_code=401, detail=build_splunk_error(401, _AUTH_FAILED))

        if authorization.lower().startswith("bearer "):
            token = authorization[7:]
            username = _resolve_session(token)
            if username:
                user = splunk_user_repo.get(username)
                if user:
                    return {"username": user.username, "roles": user.roles}
            raise HTTPException(status_code=401, detail=build_splunk_error(401, _AUTH_FAILED))

        # Basic auth
        if authorization.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(authorization[6:]).decode()
                uname, passwd = decoded.split(":", 1)
                user = splunk_user_repo.authenticate(uname, passwd)
                if user:
                    return {"username": user.username, "roles": user.roles}
            except Exception:
                pass
            raise HTTPException(status_code=401, detail=_UNAUTHORIZED, headers=_BASIC_CHALLENGE)

    raise HTTPException(status_code=401, detail=_UNAUTHORIZED, headers=_BASIC_CHALLENGE)


_ADMIN_ROLES: frozenset[str] = frozenset({"admin", "sc_admin"})

#: The roles that may put events into an index. Measured on Splunk 10.4.2: a
#: `power` account posting to `receivers/simple` is answered 200 and a `user`
#: account 403, so the plain `user` role reads and does not ingest. mockdr
#: took an event from anyone who could log in, which is the quieter half of
#: getting authorisation wrong — a client tested here learns nothing about
#: what production will refuse.
_INGEST_ROLES: frozenset[str] = _ADMIN_ROLES | {"power", "can_delete"}
"""Roles allowed to manage indexes, HEC tokens and KV Store collections.

``sc_admin`` is Splunk Cloud's administrator role and carries the same
management capabilities there as ``admin`` does on-premises.
"""


async def require_splunk_admin(
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Require an administrator role for management operations.

    This dependency should be composed with ``require_splunk_auth`` via
    ``Depends``.

    Args:
        current_user: Injected by ``require_splunk_auth``.

    Returns:
        The authenticated user dict.

    Raises:
        HTTPException: 403 if the user holds no administrator role.
    """
    if not _ADMIN_ROLES.intersection(current_user.get("roles", [])):
        user = current_user.get("username", "")
        raise HTTPException(
            status_code=403,
            detail=build_splunk_error(
                403,
                f"You (user={user}) do not have permission to perform this "
                f"operation (requires capability: admin_all_objects).",
            ),
        )
    return current_user


async def require_splunk_ingest(
    current_user: dict = Depends(require_splunk_auth),
) -> dict:
    """Require a role that may write events into an index.

    splunkd's refusal here is not the management one: it answers 403 with a
    ``WARN`` message and no mention of a capability, which is what a client
    parses.

    Args:
        current_user: Injected by ``require_splunk_auth``.

    Returns:
        The authenticated user dict.

    Raises:
        HTTPException: 403 if the user may read but not ingest.
    """
    if not _INGEST_ROLES.intersection(current_user.get("roles", [])):
        raise HTTPException(
            status_code=403,
            detail={"messages": [
                {"type": "WARN", "text": "insufficient permission to access this resource"},
            ]},
        )
    return current_user


async def require_hec_auth(
    authorization: str | None = Header(None),
    token: str | None = Query(default=None),
) -> dict:
    """Validate Splunk HEC token authentication.

    HEC takes the token in the ``Authorization: Splunk <token>`` header. It
    also reads a ``?token=`` query parameter, but only when ``inputs.conf``
    sets ``allowQueryStringAuth``, which is off by default.

    The ordering below is splunkd's, not the obvious one: the token is
    validated *first*, so an invalid token sent by query string is a 403
    ``Invalid token`` even when query-string auth is disabled, and only a
    *valid* one reaches the 400 that reports the channel is not enabled.
    Verified against Splunk 10.4.2 — see ``SPLUNK_HEC_QUERY_STRING_AUTH``.

    Args:
        authorization: The Authorization header value.
        token:         The token as a query parameter, if given.

    Returns:
        Dict with ``token_name``, ``index``, ``sourcetype`` from the token.

    Raises:
        HTTPException: 400/401/403 if the token is missing, invalid, disabled,
            or arrived by a channel this instance does not accept.
    """
    from_query = False
    if authorization and authorization.lower().startswith("splunk "):
        token_value = authorization[7:]
    elif token:
        token_value = token
        from_query = True
    else:
        raise HTTPException(
            status_code=401, detail={"text": "Token is required", "code": 2},
        )
    record = hec_token_repo.get(token_value)
    if not record:
        raise HTTPException(status_code=403, detail={"text": "Invalid token", "code": 4})
    if from_query and not SPLUNK_HEC_QUERY_STRING_AUTH:
        code, text = QUERY_STRING_AUTH_DISABLED
        raise HTTPException(status_code=400, detail={"text": text, "code": code})
    if record.disabled:
        raise HTTPException(status_code=403, detail={"text": "Token disabled", "code": 1})

    return {
        "token_name": record.name,
        "token": record.token,
        "index": record.index,
        # Surfaced so the endpoint can enforce them: the token's allowed-index
        # list and its indexer-acknowledgement setting were listed in the token
        # API but never checked on ingest.
        "indexes": record.indexes,
        "use_ack": record.use_ack,
        "sourcetype": record.sourcetype,
    }
