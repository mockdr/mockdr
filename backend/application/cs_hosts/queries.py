"""CrowdStrike Falcon Host query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_host_repo import cs_host_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_id_response


def _parse_sort(sort: str | None) -> tuple[str, bool]:
    """Parse a CrowdStrike sort string into field name and direction.

    Args:
        sort: Sort string in ``field.asc`` or ``field.desc`` format, or None.

    Returns:
        Tuple of ``(field_name, descending)`` with sensible defaults.
    """
    if not sort:
        return "last_seen", True
    parts = sort.rsplit(".", 1)
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return field_name, desc


def query_host_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query host IDs matching FQL filter.

    Returns a CrowdStrike ID response with pagination metadata.

    Args:
        filter_fql: FQL filter string, or None for all hosts.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope.
    """
    records = [asdict(h) for h in cs_host_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["device_id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_host_entities(ids: list[str]) -> dict:
    """Get full host entities by device_id list.

    Args:
        ids: List of device IDs to retrieve.

    Returns:
        CS entity response envelope containing full host dicts.
    """
    entities: list[dict] = []
    for device_id in ids:
        host = cs_host_repo.get(device_id)
        if host:
            entities.append(asdict(host))
    return build_cs_entity_response(entities)


def query_host_ids_scroll(
    filter_fql: str | None,
    offset: str | None,
    limit: int,
    sort: str | None,
) -> dict:
    """Query host IDs with scroll-based pagination.

    Uses a string offset cursor (index encoded as string) matching
    FalconPy's ``query_devices_by_filter_scroll()`` contract.

    Args:
        filter_fql: FQL filter string, or None for all hosts.
        offset:     Scroll cursor (stringified integer index), or None/empty.
        limit:      Maximum number of IDs to return per page.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response with scroll-style pagination metadata.
    """
    records = [asdict(h) for h in cs_host_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    total = len(records)

    start = int(offset) if offset else 0
    page = records[start : start + limit]
    ids = [r["device_id"] for r in page]

    next_offset = "" if start + limit >= total else str(start + limit)

    return {
        "meta": {
            "query_time": 0.01,
            "powered_by": "device-api",
            "trace_id": build_cs_id_response([], 0)["meta"]["trace_id"],
            "pagination": {
                "offset": next_offset,
                "limit": limit,
                "total": total if start == 0 else 0,
            },
        },
        "resources": ids,
        "errors": [],
    }


def get_host_count(filter_fql: str | None) -> dict:
    """Count hosts matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all hosts.

    Returns:
        CS entity response with a single resource containing the count.
    """
    records = [asdict(h) for h in cs_host_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    return build_cs_entity_response([{"count": len(records)}])
