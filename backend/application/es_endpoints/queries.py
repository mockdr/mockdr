"""Elastic Security endpoint query handlers (read-only)."""
from __future__ import annotations

from repository.es_endpoint_repo import es_endpoint_repo
from utils.es_endpoint_serde import to_endpoint_entry
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_endpoint_response
from utils.nested import get_nested
from utils.serde import record_dict


def list_endpoints(
    page: int = 1,
    per_page: int = 20,
    hostname: str | None = None,
    host_os_name: str | None = None,
    agent_status: str | None = None,
    policy_id: str | None = None,
    sort_field: str = "enrolled_at",
    sort_direction: str = "desc",
) -> dict:
    """List endpoints with optional filtering and Kibana-style pagination.

    Args:
        page:           Page number (1-based).
        per_page:       Number of items per page.
        hostname:       Filter by hostname (case-insensitive substring).
        host_os_name:   Filter by OS name (case-insensitive substring).
        agent_status:   Filter by agent status (exact match).
        policy_id:      Filter by policy ID (exact match).
        sort_field:     Which of the nine sortable fields to order by.
        sort_direction: ``asc`` or ``desc``.

    Returns:
        Kibana paginated list response.
    """
    records = [record_dict(ep) for ep in es_endpoint_repo.list_all()]

    if hostname:
        hostname_lower = hostname.lower()
        records = [r for r in records if hostname_lower in r.get("hostname", "").lower()]

    if host_os_name:
        os_lower = host_os_name.lower()
        records = [r for r in records if os_lower in r.get("host_os_name", "").lower()]

    if agent_status:
        records = [r for r in records if r.get("agent_status") == agent_status]

    if policy_id:
        records = [r for r in records if r.get("policy_id") == policy_id]

    entries = [to_endpoint_entry(r) for r in records]
    # The sort runs over the *entry* shape, because that is what its field
    # names point into: `metadata.host.hostname` is a path through the
    # document Kibana returns, not through mockdr's own record.
    entries.sort(
        key=lambda entry: str(get_nested(entry, sort_field) or ""),
        reverse=sort_direction != "asc",
    )
    page_items, total = paginate_kibana(entries, page, per_page)
    return build_kibana_endpoint_response(
        page_items, page, per_page, total, sort_field, sort_direction,
    )


def get_endpoint(agent_id: str) -> dict | None:
    """Get a single endpoint by agent ID.

    Args:
        agent_id: The agent ID to look up.

    Returns:
        Endpoint dict, or None if not found.
    """
    ep = es_endpoint_repo.get(agent_id)
    if not ep:
        return None
    return to_endpoint_entry(record_dict(ep))
