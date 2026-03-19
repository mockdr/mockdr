"""Read-side handlers for Microsoft Graph Organization."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.organization_repo import graph_organization_repo
from utils.graph_response import build_graph_list_response


def list_organization() -> dict:
    """Return the organization as an OData list (always a single entry).

    Returns:
        OData list response containing one organization record.
    """
    records = [asdict(o) for o in graph_organization_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#organization",
    )
