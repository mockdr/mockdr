"""CrowdStrike Falcon Quarantine query handlers (read-only)."""
from __future__ import annotations

from repository.cs_quarantine_repo import cs_quarantine_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_id_response
from utils.cs_sort import parse_cs_sort, sort_key
from utils.nested import get_nested
from utils.serde import record_dict


def query_quarantined_file_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query quarantined file IDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all files.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field|asc`` or ``field.asc``).

    Returns:
        CS ID response envelope with quarantined file IDs.
    """
    records = [record_dict(f) for f in cs_quarantine_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = parse_cs_sort(sort, "date_created", True)
    records.sort(key=lambda r: sort_key(get_nested(r, field_name)), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_quarantined_file_entities(ids: list[str]) -> dict:
    """Get quarantined file entities by ID list.

    Args:
        ids: List of quarantined file IDs to retrieve.

    Returns:
        CS entity response envelope containing full quarantined file dicts.
    """
    entities: list[dict] = []
    for file_id in ids:
        qf = cs_quarantine_repo.get(file_id)
        if qf:
            entities.append(record_dict(qf))
    return build_cs_entity_response(entities)
