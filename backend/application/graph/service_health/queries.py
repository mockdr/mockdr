"""Read-side handlers for Microsoft Graph Service Health API."""
from __future__ import annotations

from repository.graph.service_health_repo import graph_service_health_repo
from utils.graph_response import build_graph_list_response, graph_page
from utils.serde import record_dict


def list_health_overviews(top: int = 100, skip: int = 0) -> dict:
    """Return all service health overview records.

    Args:
        top:  ``$top`` -- how many to return.
        skip: ``$skip`` -- how many to pass over first.

    Returns:
        OData list response dict.
    """
    records = [record_dict(h) for h in graph_service_health_repo.list_all()]
    page, next_link = graph_page(
        records, top, skip, resource="admin/serviceAnnouncement/healthOverviews")
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#admin/serviceAnnouncement/healthOverviews",
        next_link=next_link,
    )
