"""FastAPI dependencies for Palo Alto Cortex XDR HMAC-style API key authentication.

Cortex XDR uses API key authentication with HMAC validation.  Clients include
the following headers on every request:

* ``x-xdr-auth-id`` — the numeric key ID
* ``Authorization`` — ``SHA256(key_secret + nonce + timestamp)``
* ``x-xdr-nonce`` — a unique random string per request
* ``x-xdr-timestamp`` — Unix epoch milliseconds as a string

Three predefined roles:

* **admin** — full read/write access.
* **analyst** — read access everywhere; write access to incidents, alerts, actions.
* **viewer** — read-only access.  All mutations return 403.
"""
from __future__ import annotations

import hashlib
import hmac

from fastapi import Depends, Header, HTTPException

from domain.xdr_api_key import XdrApiKey
from repository.xdr_api_key_repo import xdr_api_key_repo
from utils.xdr_response import build_xdr_error

# ── Role sets ────────────────────────────────────────────────────────────────

_WRITE_ROLES: frozenset[str] = frozenset({"admin", "analyst"})


# ── Public dependencies ──────────────────────────────────────────────────────

async def require_xdr_auth(
    x_xdr_auth_id: str = Header(None),
    x_xdr_nonce: str = Header(None),
    x_xdr_timestamp: str = Header(None),
    authorization: str = Header(None),
) -> XdrApiKey:
    """Validate XDR HMAC authentication and return the API key record.

    Looks up the API key by ``x-xdr-auth-id`` from the ``xdr_api_keys``
    collection, then verifies that
    ``SHA256(key_secret + nonce + timestamp) == authorization``.

    Args:
        x_xdr_auth_id:   API key ID header.
        x_xdr_nonce:     Unique nonce header.
        x_xdr_timestamp: Unix epoch milliseconds header.
        authorization:   HMAC hash header.

    Returns:
        The stored API key record (dataclass with ``key_id``, ``role``, etc.).

    Raises:
        HTTPException: 401 if any header is missing or authentication fails.
    """
    if not all([x_xdr_auth_id, x_xdr_nonce, x_xdr_timestamp, authorization]):
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(
                401,
                "Missing required authentication headers",
                "Provide x-xdr-auth-id, Authorization, x-xdr-nonce, and x-xdr-timestamp",
            ),
        )

    # Look up API key by key_id using dict-based index (O(1) amortised)
    key_record = xdr_api_key_repo.get_by_key_id(x_xdr_auth_id)

    if not key_record:
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(401, "Invalid API key ID"),
        )

    # Verify HMAC: HMAC-SHA256 with key_secret as the HMAC key and
    # nonce + delimiter + timestamp as the message.
    expected = hmac.new(
        key_record.key_secret.encode(),
        (x_xdr_nonce + ":" + x_xdr_timestamp).encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, authorization):
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(401, "Authentication failed — invalid signature"),
        )

    return key_record


async def require_xdr_write(
    current_key: XdrApiKey = Depends(require_xdr_auth),
) -> XdrApiKey:
    """Require admin or analyst role for write operations.

    Args:
        current_key: Injected by ``require_xdr_auth``.

    Returns:
        The authenticated API key record.

    Raises:
        HTTPException: 403 if the key role is not permitted to write.
    """
    if current_key.role not in _WRITE_ROLES:
        raise HTTPException(
            status_code=403,
            detail=build_xdr_error(403, "Insufficient privileges for this operation"),
        )
    return current_key
