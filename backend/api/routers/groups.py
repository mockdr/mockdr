from fastapi import APIRouter, Depends, HTTPException, Query
from starlette.requests import Request

from api.auth import require_admin
from api.dto.requests import GroupCreateBody, GroupMoveAgentsBody, GroupUpdateBody
from application.agents.commands import resolve_agent_filter
from application.groups import commands as group_commands
from application.groups import queries as group_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, MAX_SKIP
from utils.documented_params import documented_openapi, documented_params
from utils.filter_selection import UnselectableFilterError
from utils.vendor_errors import build_vendor_error

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
    skip: int = Query(None, ge=0, le=MAX_SKIP),
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
    """Move the agents the body's ``filter`` selects into the group.

    The filter is an agent filter, resolved as the agent actions resolve it;
    only ``ids`` was read, so ``{"filter": {"siteIds": [...]}}`` moved
    nobody and answered ``affected: 0``.
    """
    try:
        agent_ids: list[str] = (
            (resolve_agent_filter(body.filter) if body.filter else [])
            or body.agentIds
            or []
        )
    except UnselectableFilterError as exc:
        raise HTTPException(
            status_code=400, detail=build_vendor_error("sentinelone", 400, str(exc)),
        ) from exc
    result = group_commands.move_agents_to_group(group_id, agent_ids)
    if result.get("error") == "not_found":
        raise HTTPException(status_code=404, detail="Group not found")
    return result
