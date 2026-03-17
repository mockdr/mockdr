"""Cortex XDR Endpoint query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.xdr_endpoint_repo import xdr_endpoint_repo
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply


def get_endpoints(request_data: dict) -> dict:
    """List endpoints with optional filtering and pagination.

    Supports filters on ``endpoint_status``, ``os_type``, ``hostname``,
    and ``ip``.  Pagination via ``search_from`` and ``search_to``.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching endpoints.
    """
    all_endpoints = [asdict(e) for e in xdr_endpoint_repo.list_all()]

    filters = request_data.get("filters", [])
    for f in filters:
        field = f.get("field", "")
        value = f.get("value")
        if field == "endpoint_status" and value:
            values = value if isinstance(value, list) else [value]
            all_endpoints = [e for e in all_endpoints if e["endpoint_status"] in values]
        elif field == "os_type" and value:
            values = value if isinstance(value, list) else [value]
            all_endpoints = [e for e in all_endpoints if e["os_type"] in values]
        elif field == "hostname" and value:
            values = value if isinstance(value, list) else [value]
            all_endpoints = [
                e for e in all_endpoints
                if any(v.lower() in e["endpoint_name"].lower() for v in values)
            ]
        elif field == "ip_list" and value:
            values = value if isinstance(value, list) else [value]
            all_endpoints = [
                e for e in all_endpoints
                if any(ip in values for ip in e.get("ip", []))
            ]

    # Also support top-level endpoint_id_list filter
    id_list = request_data.get("endpoint_id_list")
    if id_list:
        all_endpoints = [e for e in all_endpoints if e["endpoint_id"] in id_list]

    total = len(all_endpoints)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = all_endpoints[search_from:search_to]

    return build_xdr_list_reply(page, total_count=total, key="endpoints")


def get_policy(endpoint_id: str) -> dict | None:
    """Return a synthetic policy for the given endpoint.

    Args:
        endpoint_id: The endpoint identifier.

    Returns:
        XDR reply with policy data, or None if endpoint not found.
    """
    endpoint = xdr_endpoint_repo.get(endpoint_id)
    if not endpoint:
        return None

    policy = {
        "endpoint_id": endpoint_id,
        "policy_name": "Default Policy",
        "policy_type": "device",
        "is_default": True,
        "rules": {
            "malware_protection": True,
            "exploit_protection": True,
            "behavioral_threat_protection": True,
            "restriction_profile": "moderate",
        },
    }
    return build_xdr_reply(policy)
