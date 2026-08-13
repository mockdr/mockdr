"""Tenant-scoped URL handling for the Entra ID token endpoints.

Real Microsoft Entra ID exposes the client-credentials token endpoint under a
tenant-scoped URL::

    https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

``{tenant}`` is a tenant GUID *or* one of the tenant's verified domain names.
The multi-tenant aliases (``common``, ``organizations``, ``consumers``) are not
valid for the client-credentials flow — Entra requires a tenant-specific
authority there.

mockdr's Graph, MDE and Sentinel token routes register the segment as an
optional path parameter, so both the bare mock URL and the faithful Entra URL
shape resolve to the same handler.
"""
from __future__ import annotations

from config import STRICT_TENANT

ENTRA_TENANT_ALIASES: frozenset[str] = frozenset({"common", "consumers", "organizations"})
"""Multi-tenant authority aliases that Entra rejects for client credentials."""


def _normalise(value: str | None) -> str:
    """Casefold and strip a tenant identifier for comparison."""
    return (value or "").strip().casefold()


def tenant_segment_matches(path_tenant: str | None, *accepted: str) -> bool:
    """Report whether a tenant path segment addresses this mock tenant.

    Args:
        path_tenant: Tenant segment taken from the URL, or ``None`` when the
                     caller used the bare (non tenant-scoped) token URL.
        *accepted:   Identifiers this tenant answers to — its GUID and any
                     verified domain names. Empty (or all blank) means the mock
                     keeps no tenant on record for this vendor, in which case
                     any concrete tenant is accepted.

    Returns:
        ``True`` if the request should be served, ``False`` if it addresses a
        tenant this mock does not host.
    """
    if path_tenant is None:
        return True

    candidate = _normalise(path_tenant)
    if not candidate or candidate in ENTRA_TENANT_ALIASES:
        return False

    known = {normalised for a in accepted if (normalised := _normalise(a))}
    if not STRICT_TENANT or not known:
        return True
    return candidate in known


def tenant_rejection_message(path_tenant: str | None) -> str:
    """Build the error description for a tenant segment that was refused.

    An unresolvable tenant mirrors the wording of Entra's ``AADSTS90002`` so
    that client-side error handling written against the real service recognises
    the response. The multi-tenant aliases resolve fine at Entra but are not
    accepted for this flow, so they get their own description rather than a
    misleading "not found".

    Args:
        path_tenant: Tenant segment that was refused.

    Returns:
        Human-readable error description.
    """
    if _normalise(path_tenant) in ENTRA_TENANT_ALIASES:
        return (
            f"The multi-tenant authority '{path_tenant}' is not supported for the "
            f"client_credentials flow. Use a tenant-specific authority — the tenant "
            f"ID or one of its verified domain names."
        )
    return (
        f"AADSTS90002: Tenant '{path_tenant}' not found. Check that you are using the "
        f"correct tenant ID or verified domain name for this directory."
    )
