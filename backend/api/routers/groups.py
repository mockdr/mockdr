from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.requests import Request

from api.auth import require_admin
from api.dto.requests import GroupCreateBody, GroupMoveAgentsBody, GroupUpdateBody
from application.groups import commands as group_commands
from application.groups import queries as group_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from utils.documented_params import documented_openapi, documented_params

router = APIRouter(tags=["Groups"])


@router.get("/groups", openapi_extra=documented_openapi("/groups"))
def list_groups(
    request: Request,
    ids: str = Query(None),
    id: str = Query(None),  # noqa: A002 - the swagger's own name
    accountIds: str = Query(None),
    siteIds: str = Query(None),
    types: str = Query(None),
    name: str = Query(None),
    updatedAt__gte: str = Query(None),
    updatedAt__lte: str = Query(None),
    updatedAt__gt: str = Query(None),
    updatedAt__lt: str = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of agent groups."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/groups"))
    return group_queries.list_groups(params, cursor, limit)


@router.get("/groups/{group_id}")
def get_group(group_id: str) -> dict:
    """Return a single group by ID."""
    result = group_queries.get_group(group_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.post("/groups")
def create_group(body: GroupCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a new group within a site."""
    return group_commands.create_group(body.data)


@router.put("/groups/{group_id}")
def update_group(
    group_id: str,
    body: GroupUpdateBody,
    _: dict = Depends(require_admin),
) -> dict:
    """Update an existing group (partial update)."""
    result = group_commands.update_group(group_id, body.data)
    if result is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return result


@router.delete("/groups/{group_id}")
def delete_group(group_id: str, _: dict = Depends(require_admin)) -> dict:
    """Delete a group by ID.

    Raises:
        HTTPException: 404 if the group is not found.
        HTTPException: 400 if the group is the default (cannot be deleted).
    """
    result = group_commands.delete_group(group_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Group not found")
    if result.get("error") == "default":
        raise HTTPException(status_code=400, detail="Cannot delete the default group")
    return result


@router.put("/groups/{group_id}/move-agents")
def move_agents_to_group(
    group_id: str,
    body: GroupMoveAgentsBody,
    _: dict = Depends(require_admin),
) -> dict:
    """Move agents to the specified group."""
    agent_ids: list[str] = (
        body.filter.get("ids")
        or body.agentIds
        or []
    )
    result = group_commands.move_agents_to_group(group_id, agent_ids)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail="Group not found")
    return result
