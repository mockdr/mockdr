"""Microsoft Graph Teams endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse

from api.graph_auth import require_graph_auth
from application.graph.teams import queries as teams_queries

router = APIRouter(tags=["Graph Teams"])


@router.get("/v1.0/teams")
async def list_teams(
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List all teams."""
    return teams_queries.list_teams()


@router.get("/v1.0/teams/{team_id}")
async def get_team(
    team_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get a single team."""
    result = teams_queries.get_team(team_id=team_id)
    if result is None:
        from fastapi import HTTPException

        from utils.graph_response import build_graph_error_response
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "NotFound",
                f"Team '{team_id}' not found",
            ),
        )
    return result


@router.get("/v1.0/teams/{team_id}/channels")
async def list_channels(
    team_id: str,
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List channels for a team."""
    return teams_queries.list_channels(team_id=team_id)


@router.get("/v1.0/teams/{team_id}/channels/{channel_id}/messages")
async def list_channel_messages(
    team_id: str,
    channel_id: str,
    top: int = Query(25, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List messages in a channel."""
    return teams_queries.list_channel_messages(
        team_id=team_id, channel_id=channel_id, top=top, skip=skip,
    )


@router.post("/v1.0/teams/{team_id}/channels/{channel_id}/messages")
async def post_channel_message(
    team_id: str,
    channel_id: str,
    request: Request,
    _: dict = Depends(require_graph_auth),
) -> JSONResponse:
    """Post a message to a channel."""
    body = await request.json()
    result = teams_queries.post_channel_message(
        team_id=team_id, channel_id=channel_id, body=body,
    )
    return JSONResponse(status_code=201, content=result)
