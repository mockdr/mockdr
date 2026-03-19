"""CrowdStrike Falcon Custom IOC query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_ioc_repo import cs_ioc_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_list_response


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
    records = [asdict(i) for i in cs_ioc_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    return build_cs_list_response(page, total, offset, limit)


def query_ioc_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query IOC IDs only (legacy ``/indicators/queries/`` pattern).

    Args:
        filter_fql: FQL filter string, or None for all IOCs.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope with IOC IDs.
    """
    from utils.cs_response import build_cs_id_response

    records = [asdict(i) for i in cs_ioc_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def device_count_for_ioc(ioc_type: str, ioc_value: str) -> dict:
    """Return a mock device count for a given IOC.

    Args:
        ioc_type:  IOC type (sha256, md5, domain, etc.).
        ioc_value: IOC value string.

    Returns:
        CS entity response with a device count resource.
    """
    count = (hash(ioc_value) % 10) + 1
    return build_cs_entity_response([{"id": ioc_value, "type": ioc_type, "device_count": count}])


def processes_ran_on(ioc_type: str, ioc_value: str, device_id: str | None) -> dict:
    """Return mock process IDs that accessed the given IOC.

    Args:
        ioc_type:  IOC type.
        ioc_value: IOC value string.
        device_id: Optional device filter.

    Returns:
        CS ID response with fake process IDs.
    """
    from utils.cs_response import build_cs_id_response

    base = abs(hash(ioc_value))
    pids = [f"pid:{base + i:016x}" for i in range(min(3, (base % 5) + 1))]
    return build_cs_id_response(pids, len(pids), 0, 100)


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
            entities.append(asdict(ioc))
    return build_cs_entity_response(entities)
