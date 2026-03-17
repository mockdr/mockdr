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

import secrets
import time
from typing import cast

from fastapi import Header, HTTPException

from repository.store import store
from utils.sentinel.response import build_arm_error

_SENTINEL_TOKEN_COLLECTION = "sentinel_oauth_tokens"
_TOKEN_TTL = 3600  # 1 hour


def create_sentinel_token(client_id: str) -> dict:
    """Create a new OAuth2 access token for the given client.

    Args:
        client_id: The authenticated client ID.

    Returns:
        Token response dict with ``access_token``, ``token_type``, ``expires_in``.
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
        "resource": "https://management.azure.com/",
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


async def require_sentinel_auth(
    authorization: str | None = Header(None),
) -> dict:
    """Validate Azure AD Bearer token and return client info.

    Args:
        authorization: The Authorization header value.

    Returns:
        Dict with ``client_id`` key.

    Raises:
        HTTPException: 401 if token is missing or invalid.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail=build_arm_error("AuthenticationFailed", "Bearer token required"),
        )

    token = authorization[7:]
    client_id = _resolve_token(token)
    if not client_id:
        raise HTTPException(
            status_code=401,
            detail=build_arm_error("AuthenticationFailed", "Invalid or expired token"),
        )

    return {"client_id": client_id}
