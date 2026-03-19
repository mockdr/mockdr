"""Read-side handlers for Microsoft Graph Windows Autopilot."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.autopilot_device_repo import graph_autopilot_device_repo
from repository.graph.autopilot_profile_repo import graph_autopilot_profile_repo
from utils.graph_response import build_graph_list_response


def list_autopilot_devices(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return Autopilot device identities with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(d) for d in graph_autopilot_device_repo.list_all()]
    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/v1.0/deviceManagement/"
        f"windowsAutopilotDeviceIdentities?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/windowsAutopilotDeviceIdentities",
        next_link=next_link,
    )


def list_autopilot_profiles(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return Autopilot deployment profiles with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(p) for p in graph_autopilot_profile_repo.list_all()]
    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/beta/deviceManagement/"
        f"windowsAutopilotDeploymentProfiles?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/beta/$metadata#deviceManagement/windowsAutopilotDeploymentProfiles",
        next_link=next_link,
    )
