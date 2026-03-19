"""Read-side handlers for Microsoft Graph Named Locations."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.named_location_repo import graph_named_location_repo
from utils.graph_response import build_graph_list_response


def list_named_locations() -> dict:
    """Return all named locations, converting ``odata_type`` to ``@odata.type``.

    Returns:
        OData list response containing named location records.
    """
    records = []
    for loc in graph_named_location_repo.list_all():
        rec = asdict(loc)
        # Convert internal field name to OData convention
        rec["@odata.type"] = rec.pop("odata_type", "")
        records.append(rec)

    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/namedLocations",
    )
