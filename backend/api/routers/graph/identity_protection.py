"""Microsoft Graph Identity Protection endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.graph_auth import require_graph_feature
from application.graph.identity_protection import queries as ip_queries
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Identity Protection"])


@router.get("/v1.0/identityProtection/riskyUsers")
async def list_risky_users(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("identityProtection")),
) -> dict:
    """List risky users flagged by Identity Protection."""
    return ip_queries.list_risky_users(
        filter_str=filter_str, top=top, skip=skip,
    )


@router.get("/v1.0/identityProtection/riskyUsers/{user_id}")
async def get_risky_user(
    user_id: str,
    _: dict = Depends(require_graph_feature("identityProtection")),
) -> dict:
    """Get a single risky user by ID."""
    result = ip_queries.get_risky_user(user_id=user_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{user_id}' does not exist or cannot be found.",
            ),
        )
    return result


@router.get("/v1.0/identityProtection/riskDetections")
async def list_risk_detections(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("identityProtection")),
) -> dict:
    """List risk detection events from Identity Protection."""
    return ip_queries.list_risk_detections(
        filter_str=filter_str, top=top, skip=skip,
    )
