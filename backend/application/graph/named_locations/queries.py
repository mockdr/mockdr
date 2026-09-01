"""Read-side handlers for Microsoft Graph Named Locations."""
from __future__ import annotations

from repository.graph.named_location_repo import graph_named_location_repo
from utils.graph_response import build_graph_list_response, graph_page
from utils.serde import record_dict


def list_named_locations(top: int = 100, skip: int = 0) -> dict:
    """Return all named locations, converting ``odata_type`` to ``@odata.type``.

    Args:
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response containing named location records.
    """
    records = []
    for loc in graph_named_location_repo.list_all():
        rec = record_dict(loc)
        # Convert internal field name to OData convention
        rec["@odata.type"] = rec.pop("odata_type", "")
        records.append(rec)

    page, next_link = graph_page(
        records, top, skip, resource="identity/conditionalAccess/namedLocations")
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/namedLocations",
        next_link=next_link,
    )
