"""Sentinel Watchlists router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import watchlists as watchlist_cmds
from application.sentinel.queries import watchlists as watchlist_queries
from utils.sentinel.response import build_arm_error, build_arm_resource

router = APIRouter(tags=["Sentinel Watchlists"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


# ── Watchlists CRUD ──────────────────────────────────────────────────────


@router.get(_WS + "/watchlists")
def list_watchlists(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List all watchlists."""
    return watchlist_queries.list_watchlists()


@router.get(_WS + "/watchlists/{alias}")
def get_watchlist(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single watchlist."""
    result = watchlist_queries.get_watchlist(alias)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Watchlist '{alias}' not found"),
        )
    return result


@router.put(_WS + "/watchlists/{alias}")
async def create_or_update_watchlist(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a watchlist."""
    body = await request.json()
    properties = body.get("properties", {})
    watchlist_cmds.create_or_update_watchlist(alias, properties)
    return watchlist_queries.get_watchlist(alias) or {}


@router.delete(_WS + "/watchlists/{alias}")
def delete_watchlist(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a watchlist."""
    if not watchlist_cmds.delete_watchlist(alias):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Watchlist '{alias}' not found"),
        )
    return {}


# ── Watchlist Items CRUD ─────────────────────────────────────────────────


@router.get(_WS + "/watchlists/{alias}/watchlistItems")
def list_watchlist_items(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List items in a watchlist."""
    result = watchlist_queries.list_watchlist_items(alias)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Watchlist '{alias}' not found"),
        )
    return result


@router.get(_WS + "/watchlists/{alias}/watchlistItems/{item_id}")
def get_watchlist_item(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    item_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single watchlist item."""
    result = watchlist_queries.get_watchlist_item(alias, item_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Watchlist item '{item_id}' not found"),
        )
    return result


@router.put(_WS + "/watchlists/{alias}/watchlistItems/{item_id}")
async def create_or_update_watchlist_item(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    item_id: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a watchlist item."""
    body = await request.json()
    properties = body.get("properties", {})
    result = watchlist_cmds.create_or_update_watchlist_item(alias, item_id, properties)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Watchlist '{alias}' not found"),
        )
    return build_arm_resource("watchlistItems", item_id, {"itemsKeyValue": result})


@router.delete(_WS + "/watchlists/{alias}/watchlistItems/{item_id}")
def delete_watchlist_item(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    item_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a watchlist item."""
    if not watchlist_cmds.delete_watchlist_item(alias, item_id):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Watchlist item '{item_id}' not found"),
        )
    return {}
