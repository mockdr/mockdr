"""Tenant-scoped URL handling for the Entra ID token endpoints.

Real Microsoft Entra ID exposes the client-credentials token endpoint under a
tenant-scoped URL::

    https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

``{tenant}`` is a tenant GUID or a verified domain name. The multi-tenant
aliases (``common``, ``organizations``, ``consumers``) are *not* valid for the
client-credentials flow — Entra requires a tenant-specific authority there.

mockdr's Graph, MDE and Sentinel token routes register the segment as an
optional path parameter, so both the bare mock URL and the faithful Entra URL
shape resolve to the same handler.
"""
from __future__ import annotations

from config import STRICT_TENANT

ENTRA_TENANT_ALIASES: frozenset[str] = frozenset({"common", "consumers", "organizations"})
"""Multi-tenant authority aliases that Entra rejects for client credentials."""


def tenant_segment_matches(path_tenant: str | None, expected_tenant: str = "") -> bool:
    """Report whether a tenant path segment addresses this mock tenant.

    Args:
        path_tenant:     Tenant segment taken from the URL, or ``None`` when the
                         caller used the bare (non tenant-scoped) token URL.
        expected_tenant: Tenant the credential belongs to. An empty string means
                         the mock keeps no tenant on record for this vendor, in
                         which case any concrete tenant is accepted.

    Returns:
        ``True`` if the request should be served, ``False`` if it addresses a
        tenant this mock does not host.
    """
    if path_tenant is None:
        return True

    candidate = path_tenant.strip().casefold()
    if not candidate or candidate in ENTRA_TENANT_ALIASES:
        return False
    if not STRICT_TENANT or not expected_tenant:
        return True
    return candidate == expected_tenant.strip().casefold()


def tenant_not_found_message(path_tenant: str | None) -> str:
    """Build the error description Entra returns for an unresolvable tenant.

    Mirrors the wording of ``AADSTS90002`` so that client-side error handling
    written against the real service recognises the response.

    Args:
        path_tenant: Tenant segment that failed to resolve.

    Returns:
        Human-readable error description.
    """
    return (
        f"AADSTS90002: Tenant '{path_tenant}' not found. Check that you are using "
        f"the correct tenant ID and that the tenant-specific authority is used — "
        f"{', '.join(sorted(ENTRA_TENANT_ALIASES))} are not supported for the "
        f"client_credentials flow."
    )
