"""Microsoft Graph Service Health API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.service_health import queries as health_queries

router = APIRouter(tags=["Graph Service Health"])


@router.get("/v1.0/admin/serviceAnnouncement/healthOverviews")
async def list_health_overviews(
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip", ge=0),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List service health overviews."""
    return health_queries.list_health_overviews(top, skip)
