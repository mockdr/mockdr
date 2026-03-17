"""Cortex XDR System query handlers (read-only)."""
from __future__ import annotations

from utils.xdr_response import build_xdr_reply


def get_tenant_info() -> dict:
    """Return synthetic tenant information.

    Returns:
        XDR reply with tenant details.
    """
    return build_xdr_reply({
        "tenant_id": "acmecorp-xdr-tenant-001",
        "tenant_name": "AcmeCorp Internal",
        "license_type": "Cortex XDR Pro per Endpoint",
        "license_expiration": 1893456000000,  # 2030-01-01
        "total_endpoints": 500,
        "used_endpoints": 25,
        "status": "active",
    })


def healthcheck() -> dict:
    """Return a simple health check response.

    Returns:
        XDR reply with OK status.
    """
    return build_xdr_reply({"status": "ok"})
