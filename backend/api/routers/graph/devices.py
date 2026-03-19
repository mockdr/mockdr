"""Microsoft Graph Device Management (Intune) endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from api.graph_auth import require_graph_feature
from application.graph.device_management import queries as device_queries
from repository.graph.managed_device_repo import graph_managed_device_repo
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Device Management"])


@router.get("/v1.0/deviceManagement/managedDevices")
async def list_managed_devices(
    request: Request,
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    count: bool = Query(False, alias="$count"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune managed devices with OData query parameters."""
    consistency_level = request.headers.get("consistencylevel")
    return device_queries.list_managed_devices(
        filter_str=filter_str, top=top, skip=skip,
        select=select, count_param=count, consistency_level=consistency_level,
    )


@router.get("/v1.0/deviceManagement/managedDevices/{device_id}")
async def get_managed_device(
    device_id: str,
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """Get a single managed device by ID."""
    result = device_queries.get_managed_device(device_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{device_id}' does not exist or cannot be found.",
            ),
        )
    return result


@router.get("/v1.0/deviceManagement/detectedApps")
async def list_detected_apps(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List detected applications across managed devices."""
    return device_queries.list_detected_apps(top=top, skip=skip)


@router.get("/v1.0/deviceManagement/detectedApps/{app_id}/managedDevices")
async def list_detected_app_devices(
    app_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List managed devices that have a specific detected app installed."""
    return device_queries.get_detected_app_devices(app_id)


# ---------------------------------------------------------------------------
# Device actions
# ---------------------------------------------------------------------------


def _require_device(device_id: str) -> None:
    """Raise 404 if the managed device does not exist."""
    if graph_managed_device_repo.get(device_id) is None:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{device_id}' does not exist or cannot be found.",
            ),
        )


@router.post("/v1.0/deviceManagement/managedDevices/{device_id}/wipe")
async def wipe_device(
    device_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> Response:
    """Wipe a managed device."""
    _require_device(device_id)
    return Response(status_code=204)


@router.post("/v1.0/deviceManagement/managedDevices/{device_id}/retire")
async def retire_device(
    device_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> Response:
    """Retire a managed device."""
    _require_device(device_id)
    return Response(status_code=204)


@router.post("/v1.0/deviceManagement/managedDevices/{device_id}/syncDevice")
async def sync_device(
    device_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> Response:
    """Trigger a sync on a managed device."""
    _require_device(device_id)
    return Response(status_code=204)


@router.post("/v1.0/deviceManagement/managedDevices/{device_id}/rebootNow")
async def reboot_device(
    device_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> Response:
    """Reboot a managed device."""
    _require_device(device_id)
    return Response(status_code=204)


@router.post("/v1.0/deviceManagement/managedDevices/{device_id}/windowsDefenderScan")
async def windows_defender_scan(
    device_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> Response:
    """Trigger a Windows Defender scan on a managed device."""
    _require_device(device_id)
    return Response(status_code=204)


@router.post("/v1.0/deviceManagement/managedDevices/{device_id}/windowsDefenderUpdateSignatures")
async def windows_defender_update_signatures(
    device_id: str,
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> Response:
    """Trigger a Windows Defender signature update on a managed device."""
    _require_device(device_id)
    return Response(status_code=204)
