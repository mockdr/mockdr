"""Elastic Security endpoint query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.es_endpoint_repo import es_endpoint_repo
from utils.es_pagination import paginate_kibana
from utils.es_response import build_kibana_list_response


def list_endpoints(
    page: int = 1,
    per_page: int = 20,
    hostname: str | None = None,
    host_os_name: str | None = None,
    agent_status: str | None = None,
    policy_id: str | None = None,
) -> dict:
    """List endpoints with optional filtering and Kibana-style pagination.

    Args:
        page:          Page number (1-based).
        per_page:      Number of items per page.
        hostname:      Filter by hostname (case-insensitive substring).
        host_os_name:  Filter by OS name (case-insensitive substring).
        agent_status:  Filter by agent status (exact match).
        policy_id:     Filter by policy ID (exact match).

    Returns:
        Kibana paginated list response.
    """
    records = [asdict(ep) for ep in es_endpoint_repo.list_all()]

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

    page_items, total = paginate_kibana(records, page, per_page)
    return build_kibana_list_response(page_items, page, per_page, total)


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
    return asdict(ep)
