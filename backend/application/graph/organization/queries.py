"""Read-side handlers for Microsoft Graph Organization."""
from __future__ import annotations

from repository.graph.organization_repo import graph_organization_repo
from utils.graph_response import build_graph_list_response, graph_page
from utils.serde import record_dict


def list_organization(top: int = 100, skip: int = 0) -> dict:
    """Return the organization as an OData list (always a single entry).

    Args:
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response containing one organization record.
    """
    records = [record_dict(o) for o in graph_organization_repo.list_all()]
    page, next_link = graph_page(records, top, skip, resource="organization")
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#organization",
        next_link=next_link,
    )
