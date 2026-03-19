"""Read-side handlers for Microsoft Graph Device Management / Intune."""
from __future__ import annotations

from dataclasses import asdict

from repository.graph.detected_app_repo import graph_detected_app_repo
from repository.graph.managed_device_repo import graph_managed_device_repo
from repository.store import store
from utils.graph_odata import (
    apply_graph_filter,
    apply_odata_count,
    apply_odata_orderby,
    apply_odata_select,
)
from utils.graph_response import build_graph_list_response


def list_managed_devices(
    filter_str: str | None = None,
    top: int = 100,
    skip: int = 0,
    orderby: str | None = None,
    select: str | None = None,
    count_param: bool | str | None = None,
    consistency_level: str | None = None,
) -> dict:
    """Return managed devices with OData query support.

    Args:
        filter_str:        OData ``$filter`` expression.
        top:               Page size (``$top``).
        skip:              Number of records to skip (``$skip``).
        orderby:           OData ``$orderby`` expression.
        select:            Comma-separated field list (``$select``).
        count_param:       Value of ``$count`` query parameter.
        consistency_level: Value of the ``ConsistencyLevel`` header.

    Returns:
        OData list response dict.
    """
    records = [asdict(d) for d in graph_managed_device_repo.list_all()]

    if filter_str:
        records = apply_graph_filter(records, filter_str)

    records = apply_odata_orderby(records, orderby)
    count = apply_odata_count(records, count_param, consistency_level)
    total = len(records)
    page = records[skip : skip + top]
    page = apply_odata_select(page, select)
    next_link = (
        f"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/managedDevices",
        next_link=next_link,
        count=count,
    )


def get_managed_device(device_id: str) -> dict | None:
    """Return a single managed device by ID.

    Args:
        device_id: The managed device's ``id``.

    Returns:
        Device dict or ``None`` if not found.
    """
    device = graph_managed_device_repo.get(device_id)
    if device is None:
        return None
    return asdict(device)


def list_detected_apps(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return detected apps with pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(a) for a in graph_detected_app_repo.list_all()]
    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/deviceManagement/detectedApps?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#deviceManagement/detectedApps",
        next_link=next_link,
    )


def get_detected_app_devices(app_id: str) -> dict:
    """Return managed devices that have a specific detected app installed.

    Reads device IDs from the ``graph_detected_app_devices`` collection,
    then looks up each device from the managed device repo.

    Args:
        app_id: The detected app's ``id``.

    Returns:
        OData list response containing managed device dicts.
    """
    device_ids = store.get("graph_detected_app_devices", app_id)
    devices: list[dict] = []
    if isinstance(device_ids, list):
        for did in device_ids:
            device = graph_managed_device_repo.get(did)
            if device is not None:
                devices.append(asdict(device))

    return build_graph_list_response(
        value=devices,
        context=f"https://graph.microsoft.com/v1.0/$metadata#deviceManagement/detectedApps('{app_id}')/managedDevices",
    )
