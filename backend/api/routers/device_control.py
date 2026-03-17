from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin
from api.dto.requests import (
    DeviceControlCreateBody,
    DeviceControlDeleteBody,
    DeviceControlUpdateBody,
)
from application.device_control import commands as dc_commands
from application.device_control import queries as dc_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Device Control"])


@router.post("/device-control")
def create_device_control_rule(
    body: DeviceControlCreateBody, _: dict = Depends(require_admin),
) -> dict:
    """Create a new device control rule."""
    return dc_commands.create_rule(body.data)


@router.put("/device-control/{rule_id}")
def update_device_control_rule(
    rule_id: str, body: DeviceControlUpdateBody,
    _: dict = Depends(require_admin),
) -> dict:
    """Update an existing device control rule by ID."""
    result = dc_commands.update_rule(rule_id, body.data)
    if result is None:
        raise HTTPException(status_code=404, detail="Device control rule not found")
    return result


@router.delete("/device-control")
def delete_device_control_rules(
    body: DeviceControlDeleteBody, _: dict = Depends(require_admin),
) -> dict:
    """Delete device control rules matching filter.ids."""
    ids: list[str] = body.filter.get("ids") or []
    if not ids:
        raise HTTPException(status_code=400, detail="filter.ids required")
    affected = dc_commands.delete_rules(ids)
    return {"data": {"affected": affected}}


@router.get("/device-control")
def list_device_control_rules(
    ids: str = Query(None),
    siteIds: str = Query(None),
    deviceTypes: str = Query(None),
    statuses: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of device control rules."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return dc_queries.list_rules(params, cursor, limit)
