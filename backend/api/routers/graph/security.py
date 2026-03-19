"""Microsoft Graph Security API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response

from api.graph_auth import require_graph_feature
from application.graph.security import queries as sec_queries
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Security"])


# ── Alerts v2 ─────────────────────────────────────────────────────────────────

@router.get("/v1.0/security/alerts_v2")
async def list_alerts_v2(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("security/alerts_v2")),
) -> dict:
    """List security alerts v2."""
    return sec_queries.list_alerts_v2(
        filter_str=filter_str, top=top, skip=skip,
        orderby=orderby, select=select,
    )


@router.get("/v1.0/security/alerts_v2/{alert_id}")
async def get_alert_v2(
    alert_id: str,
    _: dict = Depends(require_graph_feature("security/alerts_v2")),
) -> dict:
    """Get a single security alert v2 by ID."""
    result = sec_queries.get_alert_v2(alert_id=alert_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{alert_id}' does not exist or cannot be found.",
            ),
        )
    return result


@router.patch("/v1.0/security/alerts_v2/{alert_id}")
async def update_alert_v2(
    alert_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_graph_feature("security/alerts_v2")),
) -> dict:
    """Update a security alert v2 (status, assignedTo, classification, determination)."""
    result = sec_queries.update_alert_v2(alert_id=alert_id, body=body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{alert_id}' does not exist or cannot be found.",
            ),
        )
    return result


# ── Incidents ─────────────────────────────────────────────────────────────────

@router.get("/v1.0/security/incidents")
async def list_incidents(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    expand: str = Query(None, alias="$expand"),
    _: dict = Depends(require_graph_feature("security/incidents")),
) -> dict:
    """List security incidents."""
    return sec_queries.list_incidents(
        filter_str=filter_str, top=top, skip=skip,
        orderby=orderby, select=select, expand=expand,
    )


@router.get("/v1.0/security/incidents/{incident_id}")
async def get_incident(
    incident_id: str,
    expand: str = Query(None, alias="$expand"),
    _: dict = Depends(require_graph_feature("security/incidents")),
) -> dict:
    """Get a single security incident by ID."""
    result = sec_queries.get_incident(incident_id=incident_id, expand=expand)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{incident_id}' does not exist or cannot be found.",
            ),
        )
    return result


# ── Advanced Hunting ──────────────────────────────────────────────────────────

@router.post("/v1.0/security/runHuntingQuery")
async def run_hunting_query(
    body: dict = Body(...),
    _: dict = Depends(require_graph_feature("security/runHuntingQuery")),
) -> dict:
    """Execute an advanced hunting query."""
    return sec_queries.run_hunting_query(body=body)


# ── Secure Scores ────────────────────────────────────────────────────────────

@router.get("/v1.0/security/secureScores")
async def list_secure_scores(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("security/secureScores")),
) -> dict:
    """List secure score snapshots."""
    return sec_queries.list_secure_scores(top=top, skip=skip)


# ── TI Indicators ────────────────────────────────────────────────────────────

@router.get("/v1.0/security/tiIndicators")
async def list_ti_indicators(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("security/tiIndicators")),
) -> dict:
    """List threat intelligence indicators."""
    return sec_queries.list_ti_indicators(
        filter_str=filter_str, top=top, skip=skip,
    )


@router.post("/v1.0/security/tiIndicators")
async def create_ti_indicator(
    body: dict = Body(...),
    _: dict = Depends(require_graph_feature("security/tiIndicators")),
) -> dict:
    """Create a new threat intelligence indicator."""
    return sec_queries.create_ti_indicator(body=body)


@router.delete("/v1.0/security/tiIndicators/{indicator_id}")
async def delete_ti_indicator(
    indicator_id: str,
    _: dict = Depends(require_graph_feature("security/tiIndicators")),
) -> Response:
    """Delete a threat intelligence indicator."""
    deleted = sec_queries.delete_ti_indicator(indicator_id=indicator_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_graph_error_response(
                "NotFound",
                f"Resource '{indicator_id}' does not exist or cannot be found.",
            ),
        )
    return Response(status_code=204)
