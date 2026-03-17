"""CrowdStrike Falcon Detection query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.cs_detection_repo import cs_detection_repo
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
        return "last_behavior", True
    parts = sort.rsplit(".", 1)
    field_name = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"
    return field_name, desc


def query_detection_ids(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
) -> dict:
    """Query detection IDs matching FQL filter.

    Args:
        filter_fql: FQL filter string, or None for all detections.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of IDs to return.
        sort:       Sort string (``field.asc`` or ``field.desc``).

    Returns:
        CS ID response envelope.
    """
    records = [asdict(d) for d in cs_detection_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: r.get(field_name, ""), reverse=desc)
    page, total = paginate_cs(records, offset, limit)
    ids = [r["composite_id"] for r in page]
    return build_cs_id_response(ids, total, offset, limit)


def get_detection_entities(ids: list[str]) -> dict:
    """Get full detection entities by composite_id list.

    Args:
        ids: List of composite detection IDs to retrieve.

    Returns:
        CS entity response envelope containing full detection dicts.
    """
    entities: list[dict] = []
    for composite_id in ids:
        detection = cs_detection_repo.get(composite_id)
        if detection:
            entities.append(asdict(detection))
    return build_cs_entity_response(entities)
