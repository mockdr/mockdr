"""Read-side handlers for Microsoft Graph Service Principals."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.service_principal_repo import graph_service_principal_repo
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_orderby,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response


def list_service_principals(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
) -> dict:
    """Return service principals with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression.
        select:     Comma-separated field list (``$select``).

    Returns:
        OData list response dict.
    """
    records = [asdict(sp) for sp in graph_service_principal_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        f"https://graph.microsoft.com/v1.0/servicePrincipals?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#servicePrincipals",
        next_link=next_link,
    )
