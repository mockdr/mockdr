"""CrowdStrike Falcon Custom IOC query handlers (read-only)."""
from __future__ import annotations

from repository.cs_ioc_repo import cs_ioc_repo
from utils.cs_fql import apply_fql
from utils.cs_pagination import decode_page_token, encode_page_token, paginate_cs
from utils.cs_response import build_cs_entity_response, build_cs_list_response
from utils.cs_sort import parse_cs_sort, sort_key
from utils.nested import get_nested
from utils.serde import record_dict


def _parse_sort(sort: str | None) -> tuple[str, bool]:
    """Parse a CrowdStrike sort (``field|asc`` or ``field.asc``) — see ``utils.cs_sort``."""
    return parse_cs_sort(sort, "modified_on", True)


def search_iocs(
    filter_fql: str | None,
    offset: int,
    limit: int,
    sort: str | None,
    after: str | None = None,
) -> dict:
    """Search custom IOCs with FQL filter.

    Returns a combined response with full entities and pagination metadata,
    matching the ``/iocs/combined/indicator/v1`` endpoint.

    Args:
        filter_fql: FQL filter string, or None for all IOCs.
        offset:     Zero-based pagination offset.
        limit:      Maximum number of entities to return.
        sort:       Sort string (``field|asc`` or ``field.asc``).
        after:      Opaque token from the previous page's
                    ``meta.pagination.after``; when given it, not ``offset``,
                    says where the page starts.

    Returns:
        CS list response envelope with full IOC entities and pagination.
    """
    records = [record_dict(i) for i in cs_ioc_repo.list_all()]
    if filter_fql:
        records = apply_fql(records, filter_fql)
    field_name, desc = _parse_sort(sort)
    records.sort(key=lambda r: sort_key(get_nested(r, field_name)), reverse=desc)
    start = decode_page_token(after) if after else offset
    page, total = paginate_cs(records, start, limit)
    response = build_cs_list_response(page, total, start, limit)
    response["meta"]["pagination"]["after"] = (
        encode_page_token(start + limit) if start + limit < total else "")
    return response


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
