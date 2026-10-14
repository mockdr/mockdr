"""Cortex XDR Endpoint query handlers (read-only)."""
from __future__ import annotations

import time

from application import bridge
from domain.xdr_endpoint import (
    AGENT_ISOLATED,
    AGENT_PENDING_ISOLATION,
    AGENT_PENDING_ISOLATION_CANCELLATION,
    AGENT_UNISOLATED,
)
from repository.xdr_endpoint_repo import xdr_endpoint_repo
from utils.nested import get_nested
from utils.serde import record_dict
from utils.xdr_filters import apply_xdr_filters, apply_xdr_sort
from utils.xdr_response import (
    XDR_MAX_PAGE,
    build_xdr_list_reply,
    build_xdr_reply,
    page_bounds,
    serialise_endpoint,
)

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


#: What a pending isolation state settles into once the agent acknowledges.
#: The endpoint flipped at once before, and spelled its state `isolated` —
#: so a playbook that isolates and polls `is_isolated` for `AGENT_ISOLATED`
#: (XSOAR CortexXDRIR, `xdr-endpoint-isolate`) never saw it arrive, and the
#: pending branches CoreIRApiModule has for both directions never ran.
_SETTLES_INTO = {
    AGENT_PENDING_ISOLATION: AGENT_ISOLATED,
    AGENT_PENDING_ISOLATION_CANCELLATION: AGENT_UNISOLATED,
}

#: How long the agent takes to acknowledge, so a client that polls twice sees
#: the state move rather than finding it already done — the Falcon mount's
#: containment waits the same.
_SETTLE_SECONDS = 1.0

#: The `isolate` filter takes the lower-case words (CoreIRApiModule sends
#: `{"field": "isolate", "operator": "in", "value": ["isolated"]}`), while
#: the endpoint serves the `AGENT_*` state.
_ISOLATE_FILTER_VALUES = {"isolated": AGENT_ISOLATED, "unisolated": AGENT_UNISOLATED}


def settle_isolation(endpoint: object, *, now: bool = False) -> object:
    """Move an endpoint out of a pending isolation state once its agent has answered.

    Args:
        endpoint: The endpoint record.
        now:      Settle regardless of the wait — the isolation action was
                  reported complete, so the endpoint must agree.

    Returns:
        The endpoint, settled or not.
    """
    settled = _SETTLES_INTO.get(str(getattr(endpoint, "is_isolated", "")))
    if settled is None:
        return endpoint
    requested = getattr(endpoint, "isolation_requested_at", None) or 0
    if not now and time.time() * 1000 - requested <= _SETTLE_SECONDS * 1000:
        return endpoint
    endpoint.is_isolated = settled  # type: ignore[attr-defined]
    endpoint.isolation_requested_at = None  # type: ignore[attr-defined]
    if settled == AGENT_UNISOLATED:
        endpoint.isolated_date = None  # type: ignore[attr-defined]
    xdr_endpoint_repo.save(endpoint)  # type: ignore[arg-type]
    # The agent answered about a second after it was asked, whoever noticed
    # and whenever: the SIEM gets the change dated then.
    answered = requested / 1000 + _SETTLE_SECONDS if requested else None
    bridge.xdr_endpoint_changed(
        endpoint, at=min(answered, time.time()) if answered else None,
    )
    return endpoint


def settle_due() -> int:
    """Settle every endpoint whose agent has answered; how many settled."""
    done = 0
    for endpoint in xdr_endpoint_repo.list_all():
        before = endpoint.is_isolated
        if before not in _SETTLES_INTO:
            continue
        if getattr(settle_isolation(endpoint), "is_isolated", before) != before:
            done += 1
    return done


def _translated_filters(filters: object) -> object:
    """The request's filters, with `isolate` values spelled as the record holds them."""
    if not isinstance(filters, list):
        return filters
    out = []
    for entry in filters:
        if isinstance(entry, dict) and entry.get("field") == "isolate":
            value = entry.get("value")
            values = value if isinstance(value, list) else [value]
            mapped = [_ISOLATE_FILTER_VALUES.get(str(v).lower(), v) for v in values]
            entry = {**entry, "value": mapped if isinstance(value, list) else mapped[0]}
        out.append(entry)
    return out


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
        [settle_isolation(e) for e in xdr_endpoint_repo.list_all()],
        _translated_filters(request_data.get("filters")),  # type: ignore[arg-type]
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
    search_from, search_to = page_bounds(request_data, XDR_MAX_PAGE)
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
