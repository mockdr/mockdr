"""CrowdStrike Falcon Host Group query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_host_group_repo import cs_host_group_repo
from repository.cs_host_repo import cs_host_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import (
    build_cs_entity_response,
    build_cs_id_response,
    build_cs_list_response,
)


def _parse_sort(sort: str | None) -> tuple[str, bool]:
    """Parse a CrowdStrike sort string into field name and direction.

    Args:
        sort: Sort string in ``field.asc`` or ``field.desc`` format, or None.

    Returns:
        Tuple of ``(field_name, descending)`` with sensible defaults.
    """
    if not sort:
        return "name", False
    parts = sort.rsplit(".", 1)
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return field_name, desc


def query_host_group_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query host group IDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all groups.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope.
    """
    records = [asdict(g) for g in cs_host_group_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_host_group_entities(ids: list[str]) -> dict:
    """Get host group entities by ID list.

    Args:
        ids: List of host group IDs to retrieve.

    Returns:
        CS entity response envelope containing full host group dicts.
    """
    entities: list[dict] = []
    for group_id in ids:
        group = cs_host_group_repo.get(group_id)
        if group:
            entities.append(asdict(group))
    return build_cs_entity_response(entities)


def list_host_groups(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Combined query returning full entities with pagination.

    Matches the ``/host-group/combined/host-groups/v1`` endpoint pattern.

    Args:
        filter_fql: FQL filter string, or None for all groups.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of entities to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS list response envelope with full entities and pagination.
    """
    records = [asdict(g) for g in cs_host_group_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    return build_cs_list_response(page, total, offset, limit)


def list_group_members(
    group_id: str,
    filter_fql: str | None,
    offset: int,
    limit: int,
) -> dict:
    """List host members of a group.

    Finds all hosts whose ``groups`` list contains the given group ID,
    then applies optional FQL filtering and pagination.

    Args:
        group_id:   ID of the host group.
        filter_fql: FQL filter string to further filter group members.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of host entities to return.

    Returns:
        CS list response envelope with host entities and pagination.
    """
    all_hosts = [asdict(h) for h in cs_host_repo.list_all()]
    members = [h for h in all_hosts if group_id in h.get("groups", [])]
    if filter_fql:
        members = apply_fql(members, filter_fql)
    page, total = paginate_cs(members, offset, limit)
    return build_cs_list_response(page, total, offset, limit)
