"""Read-side handlers for Microsoft Graph Intune Enrollment / Update Rings / Device Categories."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.device_category_repo import graph_device_category_repo
from repository.graph.enrollment_restriction_repo import graph_enrollment_restriction_repo
from repository.graph.update_ring_repo import graph_update_ring_repo
from utils.graph_response import build_graph_list_response


def list_update_rings(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return Windows Update for Business configurations with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(r) for r in graph_update_ring_repo.list_all()]
    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/beta/deviceManagement/"
        f"windowsUpdateForBusinessConfigurations?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/beta/$metadata#deviceManagement/windowsUpdateForBusinessConfigurations",
        next_link=next_link,
    )


def list_enrollment_restrictions(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return device enrollment configurations with pagination.

    Converts the internal ``odata_type`` field to ``@odata.type``.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = []
    for restriction in graph_enrollment_restriction_repo.list_all():
        rec = asdict(restriction)
        rec["@odata.type"] = rec.pop("odata_type", "")
        records.append(rec)

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/v1.0/deviceManagement/"
        f"deviceEnrollmentConfigurations?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceEnrollmentConfigurations",
        next_link=next_link,
    )


def list_device_categories(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return device categories with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(c) for c in graph_device_category_repo.list_all()]
    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/deviceManagement/deviceCategories?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCategories",
        next_link=next_link,
    )
