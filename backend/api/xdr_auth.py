"""FastAPI dependencies for Palo Alto Cortex XDR API key authentication.

Cortex XDR offers two authentication levels, both supported here.

**Standard** — the API key is sent verbatim:

* ``x-xdr-auth-id`` — the numeric key ID
* ``Authorization`` — the API key itself

**Advanced** — the key is never transmitted; a per-request digest is sent
instead, over the plain concatenation of key, nonce and timestamp:

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
from utils.xdr_response import XDR_ERR_UNAUTHORIZED, build_xdr_error

# ── Role sets ────────────────────────────────────────────────────────────────

_WRITE_ROLES: frozenset[str] = frozenset({"admin", "analyst"})


# ── Public dependencies ──────────────────────────────────────────────────────

async def require_xdr_auth(
    x_xdr_auth_id: str = Header(None),
    x_xdr_nonce: str = Header(None),
    x_xdr_timestamp: str = Header(None),
    authorization: str = Header(None),
) -> XdrApiKey:
    """Validate XDR authentication and return the API key record.

    Looks up the API key by ``x-xdr-auth-id`` from the ``xdr_api_keys``
    collection, then accepts either authentication level: standard, where
    ``authorization`` is the API key itself, or advanced, where it is
    ``SHA256(key_secret + nonce + timestamp)``.

    Args:
        x_xdr_auth_id:   API key ID header.
        x_xdr_nonce:     Unique nonce header (advanced auth only).
        x_xdr_timestamp: Unix epoch milliseconds header (advanced auth only).
        authorization:   API key or its per-request digest.

    Returns:
        The stored API key record (dataclass with ``key_id``, ``role``, etc.).

    Raises:
        HTTPException: 401 if headers are missing or authentication fails.
    """
    if not x_xdr_auth_id or not authorization:
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(
                401,
                XDR_ERR_UNAUTHORIZED,
                "Provide x-xdr-auth-id and Authorization; advanced authentication "
                "additionally requires x-xdr-nonce and x-xdr-timestamp",
            ),
        )

    # Look up API key by key_id using dict-based index (O(1) amortised)
    key_record = xdr_api_key_repo.get_by_key_id(x_xdr_auth_id)

    if not key_record:
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(401, XDR_ERR_UNAUTHORIZED, "Unknown API key id"),
        )

    # Standard authentication — the API key is sent verbatim.
    if hmac.compare_digest(key_record.key_secret, authorization):
        return key_record

    # Advanced authentication — SHA-256 over key + nonce + timestamp, plainly
    # concatenated in that order (Cortex XDR sends no delimiter).
    if not x_xdr_nonce or not x_xdr_timestamp:
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(
                401,
                XDR_ERR_UNAUTHORIZED,
                "Advanced authentication requires x-xdr-nonce and x-xdr-timestamp",
            ),
        )

    expected = hashlib.sha256(
        (key_record.key_secret + x_xdr_nonce + x_xdr_timestamp).encode(),
    ).hexdigest()

    if not hmac.compare_digest(expected, authorization):
        raise HTTPException(
            status_code=401,
            detail=build_xdr_error(401, XDR_ERR_UNAUTHORIZED, "Signature mismatch"),
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
