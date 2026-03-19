"""Read-side handlers for Microsoft Graph Compliance Policies and Device Configurations."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.compliance_policy_repo import graph_compliance_policy_repo
from repository.graph.device_configuration_repo import graph_device_configuration_repo
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response


def _convert_odata_type(rec: dict) -> dict:
    """Convert internal ``odata_type`` field to ``@odata.type``."""
    rec["@odata.type"] = rec.pop("odata_type", "")
    return rec


def list_compliance_policies(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    select: str | None = None,
) -> dict:
    """Return compliance policies with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        select:     Comma-separated field list (``$select``).

    Returns:
        OData list response dict.
    """
    records = [_convert_odata_type(asdict(p)) for p in graph_compliance_policy_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        "https://graph.microsoft.com/v1.0/deviceManagement/"
        f"deviceCompliancePolicies?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicies",
        next_link=next_link,
    )


def list_device_configurations(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    select: str | None = None,
) -> dict:
    """Return device configuration profiles with OData query support.

    Args:
        filter_str: OData ``$filter`` expression.
        top:        Page size (``$top``).
        skip:       Number of records to skip (``$skip``).
        select:     Comma-separated field list (``$select``).

    Returns:
        OData list response dict.
    """
    records = [_convert_odata_type(asdict(c)) for c in graph_device_configuration_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        f"https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceConfigurations",
        next_link=next_link,
    )
