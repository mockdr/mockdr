from fastapi import APIRouter, Body, Depends, Query

from api.auth import require_admin
from api.dto.requests import IocCreateBody, IocDeleteBody
from application.ioc import commands as ioc_commands
from application.ioc import queries as ioc_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Threat Intelligence / IOC"])


@router.get("/threat-intelligence/iocs")
def list_iocs(
    ids: str = Query(None),
    types: str = Query(None),
    sources: str = Query(None),
    value: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of IOC indicators."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return ioc_queries.list_iocs(params, cursor, limit)


@router.post("/threat-intelligence/iocs")
def create_ioc(body: dict = Body(...), _: dict = Depends(require_admin)) -> dict:
    """Create one or more IOC indicators.

    Accepts flat dict, ``{"data": {...}}``, or ``{"data": [{...}, ...]}``.
    """
    data = body.get("data", body)
    if isinstance(data, list):
        return ioc_commands.bulk_create_iocs(data)
    return ioc_commands.create_ioc(data)


@router.post("/threat-intelligence/iocs/bulk")
def bulk_create_iocs(body: IocCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Bulk-create IOC indicators from a list."""
    items = body.data if isinstance(body.data, list) else []
    return ioc_commands.bulk_create_iocs(items)


@router.delete("/threat-intelligence/iocs")
def delete_iocs(body: IocDeleteBody, _: dict = Depends(require_admin)) -> dict:
    """Delete a list of IOC indicators by uuid."""
    filt = body.filter
    ids = filt.get("uuids") or filt.get("ids", [])
    return ioc_commands.delete_iocs(ids)
