"""CrowdStrike Falcon User Management query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_user_repo import cs_user_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_id_response


def query_user_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query user UUIDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all users.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope with user UUIDs.
    """
    records = [asdict(u) for u in cs_user_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    if sort:
        parts = sort.rsplit(".", 1)
        field_name = parts[0]
        desc = len(parts) > 1 and parts[1].lower() == "desc"
    else:
        field_name, desc = "last_login_at", True
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["uuid"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_user_entities(ids: list[str]) -> dict:
    """Get full user entities by UUID list.

    Args:
        ids: List of user UUIDs to retrieve.

    Returns:
        CS entity response envelope containing full user dicts.
    """
    entities: list[dict] = []
    for user_id in ids:
        user = cs_user_repo.get(user_id)
        if user:
            entities.append(asdict(user))
    return build_cs_entity_response(entities)
