"""Microsoft Graph Groups endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.graph_auth import require_graph_auth
from application.graph.groups import queries as group_queries
from utils.graph_response import build_graph_error_response
from utils.odata_paging import directory_page_offset

router = APIRouter(tags=["Graph Groups"])


@router.get("/v1.0/groups")
async def list_groups(
    request: Request,
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Depends(directory_page_offset),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    search: str = Query(None, alias="$search"),
    count: bool = Query(False, alias="$count"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List groups with OData query parameters."""
    return group_queries.list_groups(
        filter_str=filter_str, top=top, skip=skip,
        orderby=orderby, select=select, search=search,
        count_param=count, consistency_level=request.headers.get("consistencylevel"),
    )


@router.get("/v1.0/groups/{group_id}")
async def get_group(
    group_id: str,
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get a single group by ID."""
    result = group_queries.get_group(group_id, select=select)
    if result is None:
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "Request_ResourceNotFound", f"Group '{group_id}' not found",
            ),
        )
    return result


@router.get("/v1.0/groups/{group_id}/members")
async def list_group_members(
    group_id: str,
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Depends(directory_page_offset),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List members of a group."""
    return group_queries.get_group_members(group_id, top, skip)
