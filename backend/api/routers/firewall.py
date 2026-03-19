from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin
from api.dto.requests import FirewallCreateBody, FirewallDeleteBody, FirewallUpdateBody
from application.firewall import commands as firewall_commands
from application.firewall import queries as firewall_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Firewall Control"])


@router.post("/firewall-control")
def create_firewall_rule(body: FirewallCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a new firewall control rule."""
    data = dict(body.data)
    filt = body.filter
    site_ids = filt.get("siteIds") or []
    if site_ids and not data.get("siteId"):
        data["siteId"] = site_ids[0]
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
    """Delete firewall rules matching the filter."""
    ids: list[str] = body.filter.get("ids") or []
    if not ids:
        raise HTTPException(status_code=400, detail="filter.ids required")
    affected = 0
    for rule_id in ids:
        if firewall_commands.delete_rule(rule_id) is not None:
            affected += 1
    return {"data": {"affected": affected}}


@router.get("/firewall-control")
def list_firewall_rules(
    ids: str = Query(None),
    siteIds: str = Query(None),
    statuses: str = Query(None),
    actions: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of firewall rules."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return firewall_queries.list_rules(params, cursor, limit)
