"""Read-side handlers for Microsoft Graph Administrative Units."""
from __future__ import annotations

from repository.graph.administrative_unit_repo import graph_admin_unit_repo
from utils.graph_response import build_graph_list_response, graph_page
from utils.serde import record_dict


def list_admin_units(top: int = 100, skip: int = 0) -> dict:
    """Return all administrative units as an OData list.

    Args:
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response containing administrative unit records.
    """
    records = [record_dict(au) for au in graph_admin_unit_repo.list_all()]
    page, next_link = graph_page(records, top, skip, resource="directory/administrativeUnits")
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#directory/administrativeUnits",
        next_link=next_link,
    )
