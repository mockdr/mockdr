"""Error bodies for the Entra ID token endpoint.

The token endpoint is not part of Graph or the Defender API and does not use
their OData error envelope. It speaks OAuth 2.0: a flat object with ``error``
and ``error_description``, plus the diagnostic fields Entra adds. MSAL and
every other OAuth client read exactly those keys, so a mock that wraps the
error in ``{"error": {"code": ...}}`` cannot be parsed by the library the
caller actually uses.
"""
from __future__ import annotations

import uuid

from utils.dt import utc_now

# Entra's own numeric codes for the conditions this mock can produce.
AADSTS_INVALID_CLIENT = 7000215
AADSTS_UNSUPPORTED_GRANT = 70003
AADSTS_TENANT_NOT_FOUND = 90002


def build_token_error(
    error: str,
    description: str,
    error_code: int,
) -> dict:
    """Build an OAuth 2.0 token-endpoint error body in Entra's shape.

    Args:
        error:       OAuth 2.0 error code, e.g. ``invalid_client``.
        description: Human-readable description, conventionally opening with
                     the ``AADSTS`` code.
        error_code:  Numeric AADSTS code, repeated in ``error_codes``.

    Returns:
        Flat error dict as returned by ``login.microsoftonline.com``.
    """
    return {
        "error": error,
        "error_description": description,
        "error_codes": [error_code],
        "timestamp": utc_now(),
        "trace_id": str(uuid.uuid4()),
        "correlation_id": str(uuid.uuid4()),
    }
