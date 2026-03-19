"""Read-side handlers for Microsoft Graph Intune App Management."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.app_protection_policy_repo import graph_app_protection_policy_repo
from repository.graph.mobile_app_repo import graph_mobile_app_repo
from utils.graph_odata import apply_graph_filter, apply_odata_select
from utils.graph_response import build_graph_list_response


def list_app_protection_policies(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return app protection policies with pagination.

    Converts the internal ``odata_type`` field to ``@odata.type``.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = []
    for policy in graph_app_protection_policy_repo.list_all():
        rec = asdict(policy)
        rec["@odata.type"] = rec.pop("odata_type", "")
        records.append(rec)

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/v1.0/"
        f"deviceAppManagement/managedAppPolicies?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceAppManagement/managedAppPolicies",
        next_link=next_link,
    )


def list_mobile_apps(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    select: str | None = None,
) -> dict:
    """Return mobile apps with OData query support.

    Converts the internal ``odata_type`` field to ``@odata.type``.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        select:     Comma-separated field list (``$select``).

    Returns:
        OData list response dict.
    """
    records = []
    for app in graph_mobile_app_repo.list_all():
        rec = asdict(app)
        rec["@odata.type"] = rec.pop("odata_type", "")
        records.append(rec)

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        f"https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceAppManagement/mobileApps",
        next_link=next_link,
    )
