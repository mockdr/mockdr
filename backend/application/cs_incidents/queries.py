"""CrowdStrike Falcon Incident query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_incident_repo import cs_incident_repo
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
        return "modified_timestamp", True
    parts = sort.rsplit(".", 1)
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return field_name, desc


def query_incident_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query incident IDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all incidents.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope.
    """
    records = [asdict(i) for i in cs_incident_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["incident_id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_incident_entities(ids: list[str]) -> dict:
    """Get full incident entities by incident_id list.

    Args:
        ids: List of incident IDs to retrieve.

    Returns:
        CS entity response envelope containing full incident dicts.
    """
    entities: list[dict] = []
    for incident_id in ids:
        incident = cs_incident_repo.get(incident_id)
        if incident:
            entities.append(asdict(incident))
    return build_cs_entity_response(entities)
