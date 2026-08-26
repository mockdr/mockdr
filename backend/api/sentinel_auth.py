"""FastAPI dependencies for Microsoft Sentinel Azure AD OAuth2 authentication.

Sentinel uses Azure AD client credentials grant:
1. POST ``/sentinel/oauth2/v2.0/token`` with ``client_id`` + ``client_secret``
   → returns ``access_token``
2. All subsequent requests: ``Authorization: Bearer <token>``

Pre-seeded credentials:
- Client ID: ``sentinel-mock-client-id``
- Client Secret: ``sentinel-mock-client-secret``
"""
from __future__ import annotations

import re
import secrets
import time
from datetime import date
from typing import cast

from fastapi import Header, HTTPException, Query
from starlette.requests import Request

from repository.store import store
from utils.bearer_challenge import bearer_challenge
from utils.sentinel.response import build_arm_error

_SENTINEL_TOKEN_COLLECTION = "sentinel_oauth_tokens"
_TOKEN_TTL = 3600  # 1 hour


def create_sentinel_token(client_id: str) -> dict:
    """Create a new OAuth2 access token for the given client.

    The members Entra's v2 endpoint answers with, and no more: `resource`
    belongs to the v1.0 endpoint this mount is not, and the two other Entra
    mounts in this mock — Defender and Graph, the same directory — have
    never sent it.

    Args:
        client_id: The authenticated client ID.

    Returns:
        Token response dict with ``access_token``, ``token_type``,
        ``expires_in`` and ``ext_expires_in``.
    """
    access_token = secrets.token_hex(32)
    store.save(_SENTINEL_TOKEN_COLLECTION, access_token, {
        "client_id": client_id,
        "created_at": time.time(),
    })
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": _TOKEN_TTL,
        "ext_expires_in": _TOKEN_TTL,
    }


def _resolve_token(token: str) -> str | None:
    """Return the client_id for a valid token, or None."""
    record = store.get(_SENTINEL_TOKEN_COLLECTION, token)
    if not record:
        return None
    created_at = record.get("created_at", 0)
    if time.time() - created_at > _TOKEN_TTL:
        store.delete(_SENTINEL_TOKEN_COLLECTION, token)
        return None
    return cast(str, record["client_id"])


#: Where this mount issues the tokens it asks for.
_TOKEN_PATH = "/sentinel/oauth2/v2.0/token"


async def require_sentinel_auth(
    request: Request,
    authorization: str | None = Header(None),
) -> dict:
    """Validate Azure AD Bearer token and return client info.

    Args:
        request:       The refused request, for the challenge's own URL.
        authorization: The Authorization header value.

    Returns:
        Dict with ``client_id`` key.

    Raises:
        HTTPException: 401 if token is missing or invalid.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail=build_arm_error("AuthenticationFailed", "Bearer token required"),
            headers=bearer_challenge(request, _TOKEN_PATH),
        )

    token = authorization[7:]
    client_id = _resolve_token(token)
    if not client_id:
        raise HTTPException(
            status_code=401,
            detail=build_arm_error("AuthenticationFailed", "Invalid or expired token"),
            headers=bearer_challenge(
                request, _TOKEN_PATH, "Invalid or expired token"),
        )

    return {"client_id": client_id}


# ── ARM api-version enforcement ──────────────────────────────────────────────

_API_VERSION_PATTERN = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(-preview)?$")

EARLIEST_API_VERSION = date(2019, 1, 1)
"""Floor for a plausible SecurityInsights api-version.

Pinning an exact allow-list would go stale every time Azure ships a preview, so
the mock instead accepts any well-formed date from the era in which the
Microsoft.SecurityInsights provider has existed. That still rejects what
clients actually get wrong: a missing parameter, a truncated date, or a
placeholder like ``v1``.
"""


async def require_arm_api_version(
    api_version: str | None = Query(default=None, alias="api-version"),
) -> str:
    """Require a supported ``api-version`` on ARM management-plane requests.

    Azure Resource Manager rejects any management request without an
    ``api-version`` query parameter, and rejects versions it does not serve.
    Accepting the request regardless — as a mock easily does by giving the
    parameter a default — hides a client bug that would surface immediately
    against real Azure.

    Args:
        api_version: Value of the ``api-version`` query parameter.

    Returns:
        The validated API version.

    Raises:
        HTTPException: 400 if the parameter is missing or unsupported.
    """
    if not api_version:
        raise HTTPException(
            status_code=400,
            detail=build_arm_error(
                "MissingApiVersionParameter",
                "The api-version query parameter (?api-version=) is required "
                "for all requests.",
            ),
        )

    if not _is_plausible_api_version(api_version):
        raise HTTPException(
            status_code=400,
            detail=build_arm_error(
                "InvalidApiVersionParameter",
                f"The api-version '{api_version}' is invalid. Expected a "
                f"Microsoft.SecurityInsights version such as '2024-03-01'.",
            ),
        )

    return api_version


def _is_plausible_api_version(api_version: str) -> bool:
    """Report whether a value could be a SecurityInsights api-version.

    Args:
        api_version: Raw ``api-version`` query parameter value.

    Returns:
        True if it is a well-formed date, optionally ``-preview``, no earlier
        than :data:`EARLIEST_API_VERSION`.
    """
    match = _API_VERSION_PATTERN.match(api_version)
    if not match:
        return False
    try:
        released = date(int(match[1]), int(match[2]), int(match[3]))
    except ValueError:
        return False
    return released >= EARLIEST_API_VERSION
