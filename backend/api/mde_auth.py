"""FastAPI dependencies for Microsoft Defender for Endpoint OAuth2 Bearer authentication.

MDE uses Azure AD OAuth2 client credentials flow.  Clients POST to
``/oauth2/v2.0/token`` with ``client_id``, ``client_secret``, and
``grant_type=client_credentials`` to receive a time-limited Bearer token.
All subsequent requests include the token via ``Authorization: Bearer <token>``.

Three predefined roles:

* **admin** — full read/write access.
* **analyst** — read access everywhere; write access to alert triage and
  machine actions.
* **viewer** — read-only access.  All mutations return 403.
"""
from __future__ import annotations

from typing import Any, cast

from fastapi import Depends, Header, HTTPException

from repository.store import store
from utils.mde_response import build_mde_error_response
from utils.token_expiry import is_token_expired

# ── Role sets ────────────────────────────────────────────────────────────────

_WRITE_ROLES: frozenset[str] = frozenset({"admin", "analyst"})


# ── Internal helpers ─────────────────────────────────────────────────────────

# ── Public dependencies ──────────────────────────────────────────────────────

async def require_mde_auth(authorization: str = Header(None)) -> dict:
    """Validate MDE Bearer token and return the client record.

    Extracts the token from the ``Authorization: Bearer <token>`` header,
    looks it up in the ``mde_oauth_tokens`` collection, and verifies it has
    not expired.

    Args:
        authorization: Raw ``Authorization`` header value.

    Returns:
        The stored token record dict (includes ``client_id``, ``role``, etc.).

    Raises:
        HTTPException: 401 if the token is missing, malformed, or unknown.
        HTTPException: 403 if the token has expired.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail=build_mde_error_response(
                "Unauthorized", "Access token is missing or malformed",
            ),
        )

    token = authorization[7:]
    record = store.get("mde_oauth_tokens", token)
    if not record:
        raise HTTPException(
            status_code=401,
            detail=build_mde_error_response(
                "Unauthorized", "Access token is invalid or expired",
            ),
        )

    if is_token_expired(record, key="expires_at"):
        raise HTTPException(
            status_code=401,
            detail=build_mde_error_response(
                "Unauthorized", "Access token has expired",
            ),
        )

    return cast(dict[str, Any], record)


async def require_mde_write(
    current_client: dict = Depends(require_mde_auth),
) -> dict:
    """Require admin or analyst role for write operations.

    Args:
        current_client: Injected by ``require_mde_auth``.

    Returns:
        The authenticated client record.

    Raises:
        HTTPException: 403 if the client role is not permitted to write.
    """
    if current_client.get("role") not in _WRITE_ROLES:
        raise HTTPException(
            status_code=403,
            detail=build_mde_error_response(
                "Forbidden", "Insufficient privileges for this operation",
            ),
        )
    return current_client
