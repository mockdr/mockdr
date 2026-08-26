"""CrowdStrike Falcon Custom IOC query handlers (read-only)."""
from __future__ import annotations

from repository.cs_ioc_repo import cs_ioc_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_list_response
from utils.serde import record_dict


def _parse_sort(sort: str | None) -> tuple[str, bool]:
    """Parse a CrowdStrike sort string into field name and direction.

    Args:
        sort: Sort string in ``field.asc`` or ``field.desc`` format, or None.

    Returns:
        Tuple of ``(field_name, descending)`` with sensible defaults.
    """
    if not sort:
        return "modified_on", True
    parts = sort.rsplit(".", 1)
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return field_name, desc


def search_iocs(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Search custom IOCs with FQL filter.

    Returns a combined response with full entities and pagination metadata,
    matching the ``/iocs/combined/indicator/v1`` endpoint.

    Args:
        filter_fql: FQL filter string, or None for all IOCs.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of entities to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS list response envelope with full IOC entities and pagination.
    """
    records = [record_dict(i) for i in cs_ioc_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    return build_cs_list_response(page, total, offset, limit)


def get_ioc_entities(ids: list[str]) -> dict:
    """Get IOC entities by ID list.

    Args:
        ids: List of IOC IDs to retrieve.

    Returns:
        CS entity response envelope containing full IOC dicts.
    """
    entities: list[dict] = []
    for ioc_id in ids:
        ioc = cs_ioc_repo.get(ioc_id)
        if ioc:
            entities.append(record_dict(ioc))
    return build_cs_entity_response(entities)
