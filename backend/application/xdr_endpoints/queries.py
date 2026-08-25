"""Cortex XDR Endpoint query handlers (read-only)."""
from __future__ import annotations

from repository.xdr_endpoint_repo import xdr_endpoint_repo
from utils.nested import get_nested
from utils.serde import record_dict
from utils.xdr_filters import apply_xdr_filters, apply_xdr_sort
from utils.xdr_response import build_xdr_list_reply, build_xdr_reply, serialise_endpoint

#: The filter fields Cortex publishes for the endpoints routes, mapped onto
#: the record keys that answer them. Cortex's own client builds exactly these
#: (``create_request_filters`` in demisto/content's CoreIRApiModule), and the
#: mock read four of them by hand while every other field fell through the
#: loop untouched — so a client narrowing to one ``endpoint_id_list`` was
#: handed the whole estate and had no way to tell.
_ENDPOINT_FILTER_FIELDS: dict[str, str] = {
    "endpoint_id_list": "endpoint_id",
    "endpoint_status": "endpoint_status",
    "dist_name": "installation_package",
    "ip_list": "ip",
    "public_ip_list": "public_ip",
    "group_name": "group_name",
    "platform": "os_type",
    "alias": "alias",
    "isolate": "is_isolated",
    "hostname": "endpoint_name",
    "username": "users",
    "first_seen": "first_seen",
    "last_seen": "last_seen",
    "scan_status": "scan_status",
}


def select_endpoints(request_data: dict) -> list:
    """The endpoints a request's ``filters`` block selects.

    Shared by the read routes and by the writes that name their target the
    same way — ``update_agent_name`` and the tag routes take a ``filters``
    block, not an id.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        The matching endpoint records.

    Raises:
        XdrFilterError: On an unsupported filter field or operator.
    """
    matched = apply_xdr_filters(
        xdr_endpoint_repo.list_all(), request_data.get("filters"),
        _ENDPOINT_FILTER_FIELDS,
    )
    # `endpoint_id_list` is also accepted beside `filters`, which is how the
    # isolate/unisolate bodies name their target.
    id_list = request_data.get("endpoint_id_list")
    if id_list:
        matched = [x for x in matched if get_nested(x, "endpoint_id") in id_list]
    return matched


def get_endpoints(request_data: dict) -> dict:
    """List endpoints with optional filtering and pagination.

    Args:
        request_data: The ``request_data`` dict from the POST body.

    Returns:
        XDR list reply with matching endpoints.
    """
    matched = apply_xdr_sort(select_endpoints(request_data), request_data.get("sort"))

    total = len(matched)
    search_from = request_data.get("search_from", 0)
    search_to = request_data.get("search_to", search_from + 100)
    page = [serialise_endpoint(record_dict(r)) for r in matched[search_from:search_to]]

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
