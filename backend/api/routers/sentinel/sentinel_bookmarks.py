"""Sentinel Bookmarks router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands.bookmarks import (
    create_or_update_bookmark,
    delete_bookmark,
)
from domain.sentinel.bookmark import SentinelBookmark
from repository.sentinel.bookmark_repo import sentinel_bookmark_repo
from utils.sentinel.response import build_arm_error, build_arm_list, build_arm_resource

router = APIRouter(tags=["Sentinel Bookmarks"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


def _bookmark_to_arm(bm: SentinelBookmark) -> dict:
    """Convert a SentinelBookmark to ARM format."""
    return build_arm_resource("bookmarks", bm.bookmark_id, {
        "displayName": bm.display_name,
        "notes": bm.notes,
        "query": bm.query,
        "queryResult": bm.query_result,
        "incidentInfo": {"incidentId": bm.incident_id} if bm.incident_id else None,
        "labels": bm.labels,
        "created": bm.created,
        "updated": bm.updated,
        "createdBy": {"name": bm.created_by_name},
    }, etag=bm.etag)


@router.get(_WS + "/bookmarks")
def list_all_bookmarks(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List all bookmarks."""
    bookmarks = sentinel_bookmark_repo.list_all()
    items = [_bookmark_to_arm(bm) for bm in bookmarks]
    return build_arm_list(items)


@router.get(_WS + "/bookmarks/{bookmark_id}")
def get_single_bookmark(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    bookmark_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single bookmark."""
    bm = sentinel_bookmark_repo.get(bookmark_id)
    if not bm:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Bookmark '{bookmark_id}' not found"),
        )
    return _bookmark_to_arm(bm)


@router.put(_WS + "/bookmarks/{bookmark_id}")
async def upsert_bookmark(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    bookmark_id: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a bookmark."""
    body = await request.json()
    properties = body.get("properties", {})
    bm = create_or_update_bookmark(bookmark_id, properties)
    return _bookmark_to_arm(bm)


@router.delete(_WS + "/bookmarks/{bookmark_id}")
def delete_single_bookmark(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    bookmark_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a bookmark."""
    if not delete_bookmark(bookmark_id):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Bookmark '{bookmark_id}' not found"),
        )
    return {}
