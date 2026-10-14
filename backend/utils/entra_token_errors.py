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
#: A required form field was absent from the token request.
AADSTS_MISSING_PARAMETER = 900144
#: The scope is not `{resource}/.default` for a resource this endpoint serves.
AADSTS_INVALID_SCOPE = 70011
#: No application with that client ID exists in the tenant.
AADSTS_APP_NOT_FOUND = 700016


def unknown_client_error(client_id: str, tenant: str) -> dict:
    """The body Entra answers an unknown ``client_id`` with, under ``400``.

    Entra tells an application it has never heard of apart from a known one
    with the wrong secret: ``400 unauthorized_client`` with AADSTS700016, not
    the ``401 invalid_client`` AADSTS7000215 of a bad secret. The wording is
    the one recorded verbatim in
    https://github.com/Azure/azure-sdk-for-go/issues/19966 and
    https://github.com/Azure/azure-sdk-for-python/issues/3742; the code is in
    https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes.
    """
    return build_token_error(
        "unauthorized_client",
        f"AADSTS700016: Application with identifier '{client_id}' was not found in "
        f"the directory '{tenant}'. This can happen if the application has not been "
        f"installed by the administrator of the tenant or consented to by any user "
        f"in the tenant. You may have sent your authentication request to the wrong "
        f"tenant.",
        AADSTS_APP_NOT_FOUND,
    )


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
