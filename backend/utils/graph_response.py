"""Microsoft Graph API response envelope builders.

Graph uses OData v4 conventions:
- List endpoints return ``{"@odata.context": "...", "value": [...]}``
- Single entities are returned as bare dicts (no envelope)
- Errors use ``{"error": {"code": "...", "message": "...", "innerError": {...}}}``
"""
from __future__ import annotations

import uuid
from contextvars import ContextVar

from utils.dt import utc_now
from utils.odata_paging import SKIP, page_link

#: (request-id, client-request-id) of the Graph request being served, set by
#: ``api/middleware/graph_request_id.py`` so an error body names the ids the
#: response headers carry.
graph_request_ids: ContextVar[tuple[str, str] | None] = ContextVar(
    "graph_request_ids", default=None,
)

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
    records: list[dict], top: int, skip: int, *, resource: str, cursor: str = SKIP,
) -> tuple[list[dict], str | None]:
    """One page of a collection, and the ``@odata.nextLink`` that follows it.

    Graph pages every collection, and this mock read ``$top``/``$skip`` on 22
    of its collection routes and ignored them on nine more -- so a console
    asking those nine for a page got the estate, and the parameter it sent
    did nothing at all. The nine now page the same way as the 22, through
    here rather than through nine copies of the same four lines.

    The link is the URL the client called with the cursor advanced (see
    :mod:`utils.odata_paging`), not a fixed one on graph.microsoft.com.

    Args:
        records:  The whole collection, already filtered.
        top:      ``$top`` -- how many to return.
        skip:     Where the page starts (``$skip``, or a decoded ``$skiptoken``).
        resource: The path under ``/v1.0``, used only outside a request.
        cursor:   ``$skip``, or ``$skiptoken`` for directory objects.

    Returns:
        The page, and the next link, which is None on the last page.
    """
    page = records[skip : skip + top]
    return page, page_link(
        skip + top, len(records),
        fallback=f"https://graph.microsoft.com/v1.0/{resource}", cursor=cursor,
    )


def build_graph_error_response(code: str, message: str) -> dict:
    """Build a Microsoft Graph-style error response.

    Args:
        code:    Error code string (e.g. ``"Authorization_RequestDenied"``).
        message: Human-readable error description.

    Returns:
        Graph error envelope dict.
    """
    # The ids of the request being answered, which its headers carry too; two
    # fresh GUIDs here meant `client-request-id` was never the one the caller
    # sent. Outside a Graph request there is nothing to echo.
    request_id, client_request_id = graph_request_ids.get() or (
        str(uuid.uuid4()), str(uuid.uuid4()))
    return {
        "error": {
            "code": code,
            "message": message,
            "innerError": {
                "date": utc_now(),
                "request-id": request_id,
                "client-request-id": client_request_id,
            },
        },
    }
