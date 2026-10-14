from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.requests import Request

from api.auth import require_admin
from api.dto.requests import (
    DeviceControlCreateBody,
    DeviceControlDeleteBody,
    DeviceControlUpdateBody,
)
from application.device_control import commands as dc_commands
from application.device_control import queries as dc_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MAX_SKIP
from utils.documented_params import documented_openapi, documented_params
from utils.filter_selection import UnselectableFilterError
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Device Control"])


@router.post("/device-control")
def create_device_control_rule(
    body: DeviceControlCreateBody, _: dict = Depends(require_admin),
) -> dict:
    """Create a device control rule at the scope the body's ``filter`` names."""
    return dc_commands.create_rule(body.data, body.filter)


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
    """Delete the device control rules the body's ``filter`` selects.

    ``ids`` names them; every other member selects as it does on the GET
    (``siteIds``, ``ruleName``, ``interfaces``, ...). Only ``ids`` was read,
    so a filter without it was refused as if the request named nothing.
    """
    if not body.filter:
        raise HTTPException(status_code=400, detail="filter.ids required")
    try:
        ids = dc_queries.select_rule_ids(body.filter)
    except UnselectableFilterError as exc:
        raise HTTPException(
            status_code=400, detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc
    affected = dc_commands.delete_rules(ids)
    return {"data": {"affected": affected}}


@router.get("/device-control", openapi_extra=documented_openapi("/device-control"))
def list_device_control_rules(
    request: Request,
    ids: str = Query(None),
    # `tenant=true` asks for the whole tenant rather than the caller's own
    # scope. mockdr seeds one tenant, and the account scoping a non-admin
    # token carries still applies, so the answer is the same set — but the
    # parameter is declared rather than silently dropped.
    tenant: bool = Query(None),
    siteIds: str = Query(None),
    accountIds: str = Query(None),
    deviceTypes: str = Query(None),
    actions: str = Query(None),
    deviceClasses: str = Query(None),
    statuses: str = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None, ge=0, le=MAX_SKIP),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of device control rules.

    ``actions`` and ``deviceClasses`` had FilterSpecs but were declared on no
    parameter, so FastAPI dropped them and every seeded value round-tripped to
    the full list.
    """
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/device-control"))
    return dc_queries.list_rules(params, cursor, limit)
