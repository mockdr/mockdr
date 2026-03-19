"""Read-side handlers for Microsoft Graph Applications."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.application_repo import graph_application_repo
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response


def list_applications(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    select: str | None = None,
) -> dict:
    """Return applications with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        select:     Comma-separated field list (``$select``).

    Returns:
        OData list response dict.
    """
    records = [asdict(app) for app in graph_application_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        f"https://graph.microsoft.com/v1.0/applications?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#applications",
        next_link=next_link,
    )
