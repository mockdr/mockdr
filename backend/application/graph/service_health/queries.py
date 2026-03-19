"""Read-side handlers for Microsoft Graph Service Health API."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.service_health_repo import graph_service_health_repo
from utils.graph_response import build_graph_list_response


def list_health_overviews() -> dict:
    """Return all service health overview records.

    Returns:
        OData list response dict.
    """
    records = [asdict(h) for h in graph_service_health_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#admin/serviceAnnouncement/healthOverviews",
    )
