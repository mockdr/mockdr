from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.requests import Request

from api.auth import require_admin
from api.dto.requests import FirewallCreateBody, FirewallDeleteBody, FirewallUpdateBody
from application.firewall import commands as firewall_commands
from application.firewall import queries as firewall_queries
from application.scopes import filter_scope
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MAX_SKIP
from utils.documented_params import documented_openapi, documented_params
from utils.filter_selection import UnselectableFilterError
from utils.vendor_errors import build_vendor_error

router = APIRouter(tags=["Firewall Control"])


@router.post("/firewall-control")
def create_firewall_rule(body: FirewallCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a firewall control rule at the scope the body's ``filter`` names.

    Only ``siteIds`` was read, and only into ``siteId``: a rule created for an
    account or a group came back ``scope: global``.
    """
    data = dict(body.data)
    scope = filter_scope(body.filter)
    if scope is not None and not data.get("scope"):
        data = {"scope": scope.level, "scopeId": scope.scope_id or None,
                "siteId": scope.site_id, **data}
    return firewall_commands.create_rule(data)


@router.put("/firewall-control")
def update_firewall_rules(body: FirewallUpdateBody, _: dict = Depends(require_admin)) -> dict:
    """Update firewall rules matching the filter."""
    ids: list[str] = body.filter.get("ids") or []
    if not ids:
        raise HTTPException(status_code=400, detail="filter.ids required")
    affected = 0
    for rule_id in ids:
        result = firewall_commands.update_rule(rule_id, body.data)
        if result is not None:
            affected += 1
    if affected == 0:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    return {"data": {"affected": affected}}


@router.delete("/firewall-control")
def delete_firewall_rules(body: FirewallDeleteBody, _: dict = Depends(require_admin)) -> dict:
    """Delete the firewall rules the body's ``filter`` selects, as the GET would."""
    if not body.filter:
        raise HTTPException(status_code=400, detail="filter.ids required")
    try:
        ids = firewall_queries.select_rule_ids(body.filter)
    except UnselectableFilterError as exc:
        raise HTTPException(
            status_code=400, detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc
    affected = 0
    for rule_id in ids:
        if firewall_commands.delete_rule(rule_id) is not None:
            affected += 1
    return {"data": {"affected": affected}}


@router.get("/firewall-control", openapi_extra=documented_openapi("/firewall-control"))
def list_firewall_rules(
    request: Request,
    ids: str = Query(None),
    # `tenant=true` asks for the whole tenant rather than the caller's own
    # scope. mockdr seeds one tenant, and the account scoping a non-admin
    # token carries still applies, so the answer is the same set — but the
    # parameter is declared rather than silently dropped.
    tenant: bool = Query(None),
    siteIds: str = Query(None),
    statuses: str = Query(None),
    actions: str = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None, ge=0, le=MAX_SKIP),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of firewall rules."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/firewall-control"))
    return firewall_queries.list_rules(params, cursor, limit)
