"""CrowdStrike Falcon Cases (Messaging Center) query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_case_repo import cs_case_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_id_response


def query_case_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query case IDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all cases.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope with case IDs.
    """
    records = [asdict(c) for c in cs_case_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    if sort:
        parts = sort.rsplit(".", 1)
        field_name = parts[0]
        desc = len(parts) > 1 and parts[1].lower() == "desc"
    else:
        field_name, desc = "created_time", True
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_case_entities(ids: list[str]) -> dict:
    """Get case entities by ID list.

    Args:
        ids: List of case IDs to retrieve.

    Returns:
        CS entity response envelope containing full case dicts.
    """
    entities: list[dict] = []
    for case_id in ids:
        case = cs_case_repo.get(case_id)
        if case:
            entities.append(asdict(case))
    return build_cs_entity_response(entities)
