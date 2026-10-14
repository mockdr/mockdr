"""Sentinel Watchlists router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import watchlists as watchlist_cmds
from application.sentinel.queries import watchlists as watchlist_queries
from repository.sentinel.watchlist_repo import sentinel_watchlist_repo
from utils.sentinel.response import arm_deleted, build_arm_error, build_arm_resource
from utils.vendor_errors import build_vendor_error

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
            detail=build_arm_error("ResourceNotFound", f"Watchlist '{alias}' not found"),
        )
    return result


@router.put(_WS + "/watchlists/{alias}")
async def create_or_update_watchlist(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    alias: str,
    request: Request,
    response: Response,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a watchlist."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    # Create Or Update: 201 for a new resource, 200 for an existing one.
    response.status_code = 200 if sentinel_watchlist_repo.get(alias) is not None else 201
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
) -> Response:
    """Delete a watchlist."""
    return arm_deleted(watchlist_cmds.delete_watchlist(alias))


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
            detail=build_arm_error("ResourceNotFound", f"Watchlist '{alias}' not found"),
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
            detail=build_arm_error("ResourceNotFound", f"Watchlist item '{item_id}' not found"),
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
    response: Response,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a watchlist item."""
    body = await request.json()
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
    properties = body.get("properties", {})
    existed = watchlist_queries.get_watchlist_item(alias, item_id) is not None
    result = watchlist_cmds.create_or_update_watchlist_item(alias, item_id, properties)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("ResourceNotFound", f"Watchlist '{alias}' not found"),
        )
    response.status_code = 200 if existed else 201
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
) -> Response:
    """Delete a watchlist item."""
    if watchlist_queries.get_watchlist(alias) is None:
        # The parent is missing: there is no collection to delete from.
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("ResourceNotFound", f"Watchlist '{alias}' not found"),
        )
    return arm_deleted(watchlist_cmds.delete_watchlist_item(alias, item_id))
