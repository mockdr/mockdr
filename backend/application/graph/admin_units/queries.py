"""Read-side handlers for Microsoft Graph Administrative Units."""
from __future__ import annotations

from repository.graph.administrative_unit_repo import graph_admin_unit_repo
from utils.graph_response import build_graph_list_response
from utils.serde import record_dict


def list_admin_units() -> dict:
    """Return all administrative units as an OData list.

    Returns:
        OData list response containing administrative unit records.
    """
    records = [record_dict(au) for au in graph_admin_unit_repo.list_all()]
    return build_graph_list_response(
        value=records,
        context="https://graph.microsoft.com/v1.0/$metadata#directory/administrativeUnits",
    )
