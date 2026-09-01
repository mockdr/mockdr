"""Microsoft Graph API response envelope builders.

Graph uses OData v4 conventions:
- List endpoints return ``{"@odata.context": "...", "value": [...]}``
- Single entities are returned as bare dicts (no envelope)
- Errors use ``{"error": {"code": "...", "message": "...", "innerError": {...}}}``
"""
from __future__ import annotations

import uuid

from utils.dt import utc_now

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_graph_list_response(
    value: list[dict],
    context: str = "https://graph.microsoft.com/v1.0/$metadata",
    next_link: str | None = None,
    count: int | None = None,
) -> dict:
    """Build an OData v4 list response envelope for Graph API.

    Args:
        value:     Page of resource objects.
        context:   OData context URL (cosmetic).
        next_link: Optional ``@odata.nextLink`` for pagination.
        count:     Optional ``@odata.count`` (total record count).

    Returns:
        OData list response dict.
    """
    resp: dict = {"@odata.context": context, "value": value}
    if count is not None:
        resp["@odata.count"] = count
    if next_link:
        resp["@odata.nextLink"] = next_link
    return resp


def graph_page(
    records: list[dict], top: int, skip: int, *, resource: str,
) -> tuple[list[dict], str | None]:
    """One page of a collection, and the ``@odata.nextLink`` that follows it.

    Graph pages every collection, and this mock read ``$top``/``$skip`` on 22
    of its collection routes and ignored them on nine more -- so a console
    asking those nine for a page got the estate, and the parameter it sent
    did nothing at all. The nine now page the same way as the 22, through
    here rather than through nine copies of the same four lines.

    Args:
        records:  The whole collection, already filtered.
        top:      ``$top`` -- how many to return.
        skip:     ``$skip`` -- how many to pass over first.
        resource: The path under ``/v1.0`` that the next link points back at.

    Returns:
        The page, and the next link, which is None on the last page.
    """
    page = records[skip : skip + top]
    if skip + top >= len(records):
        return page, None
    return page, f"https://graph.microsoft.com/v1.0/{resource}?$skip={skip + top}"


def build_graph_error_response(code: str, message: str) -> dict:
    """Build a Microsoft Graph-style error response.

    Args:
        code:    Error code string (e.g. ``"Authorization_RequestDenied"``).
        message: Human-readable error description.

    Returns:
        Graph error envelope dict.
    """
    return {
        "error": {
            "code": code,
            "message": message,
            "innerError": {
                "date": utc_now(),
                "request-id": str(uuid.uuid4()),
                "client-request-id": str(uuid.uuid4()),
            },
        },
    }
