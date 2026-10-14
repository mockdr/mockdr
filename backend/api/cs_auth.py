"""FastAPI dependencies for CrowdStrike OAuth2 Bearer authentication and RBAC.

CrowdStrike uses OAuth2 client credentials flow.  Clients POST to
``/oauth2/token`` with ``client_id`` + ``client_secret`` to receive a
time-limited Bearer token.  All subsequent requests include the token via
``Authorization: Bearer <token>``.

Three predefined roles:

* **admin** — full read/write access.
* **analyst** — read access everywhere; write access to detection/incident
  triage and containment actions.
* **viewer** — read-only access.  All mutations return 403.
"""
from __future__ import annotations

from typing import Any, cast

from fastapi import Depends, Header, HTTPException
from starlette.requests import Request

from repository.store import store
from utils.bearer_challenge import bearer_challenge
from utils.cs_response import build_cs_error_response
from utils.token_expiry import is_token_expired

# ── Role sets ────────────────────────────────────────────────────────────────

_WRITE_ROLES: frozenset[str] = frozenset({"admin", "analyst"})


# ── Internal helpers ─────────────────────────────────────────────────────────

# ── Public dependencies ──────────────────────────────────────────────────────

#: Where this mount issues the tokens it asks for.
_TOKEN_PATH = "/cs/oauth2/token"


async def require_cs_auth(
    request: Request, authorization: str = Header(None),
) -> dict:
    """Validate CrowdStrike Bearer token and return the client record.

    Extracts the token from the ``Authorization: Bearer <token>`` header,
    looks it up in the ``cs_oauth_tokens`` collection, and verifies it has
    not expired.

    Args:
        request:       The refused request, for the challenge's own URL.
        authorization: Raw ``Authorization`` header value.

    Returns:
        The stored token record dict (includes ``client_id``, ``role``, etc.).

    Raises:
        HTTPException: 401 if the token is missing, malformed, unknown, or
                       expired. (This said an expired token was a 403; the
                       code has always answered 401, which is the status
                       for a credential that no longer authenticates.)
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail=build_cs_error_response(
                401, "access denied, invalid bearer token",
            ),
            headers=bearer_challenge(request, _TOKEN_PATH),
        )

    token = authorization[7:]
    record = store.get("cs_oauth_tokens", token)
    if not record:
        raise HTTPException(
            status_code=401,
            detail=build_cs_error_response(
                401, "access denied, invalid bearer token",
            ),
            headers=bearer_challenge(
                request, _TOKEN_PATH, "access denied, invalid bearer token"),
        )

    if is_token_expired(record, key="expires_at"):
        raise HTTPException(
            status_code=401,
            detail=build_cs_error_response(
                401, "access denied, token expired",
            ),
        )

    return cast(dict[str, Any], record)


async def require_cs_write(
    current_client: dict = Depends(require_cs_auth),
) -> dict:
    """Require admin or analyst role for write operations.

    Args:
        current_client: Injected by ``require_cs_auth``.

    Returns:
        The authenticated client record.

    Raises:
        HTTPException: 403 if the client role is not permitted to write.
    """
    if current_client.get("role") not in _WRITE_ROLES:
        # Falcon words a call its client's scopes do not cover as "access
        # denied, authorization failed" — captured on PerformActionV2
        # (falconpy issue #1137), on a device-control policy query from a
        # client without that scope (terraform-provider-crowdstrike #24) and
        # on a call needing infrastructure-as-code:read (fcs-action #47).
        # "insufficient privileges" appears in none of them, so a client
        # matching Falcon's text to tell a scope problem from another 403
        # never matched the mock's.
        raise HTTPException(
            status_code=403,
            detail=build_cs_error_response(
                403, "access denied, authorization failed",
            ),
        )
    return current_client
