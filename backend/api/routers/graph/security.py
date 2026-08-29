"""Microsoft Graph Security API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.graph_auth import require_graph_feature, require_graph_write
from application.graph.security import queries as sec_queries
from utils.graph_response import build_graph_error_response

router = APIRouter(tags=["Graph Security"])


# ── Alerts v2 ─────────────────────────────────────────────────────────────────

@router.get("/v1.0/security/alerts_v2")
async def list_alerts_v2(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip", ge=0),
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
                "notFound",
                f"Resource '{alert_id}' does not exist or cannot be found.",
            ),
        )
    return result


@router.patch("/v1.0/security/alerts_v2/{alert_id}", dependencies=[Depends(require_graph_write)])
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
                "notFound",
                f"Resource '{alert_id}' does not exist or cannot be found.",
            ),
        )
    return result


# ── Incidents ─────────────────────────────────────────────────────────────────

@router.get("/v1.0/security/incidents")
async def list_incidents(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip", ge=0),
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
                "notFound",
                f"Resource '{incident_id}' does not exist or cannot be found.",
            ),
        )
    return result


# ── Advanced Hunting ──────────────────────────────────────────────────────────

# Two spellings, both the vendor's own.  The documented request line is
# `POST /security/runHuntingQuery`; the published OpenAPI carries only the
# fully qualified `/security/microsoft.graph.security.runHuntingQuery`,
# because the action lives in the `microsoft.graph.security` namespace — and
# the official Graph SDKs are generated from that OpenAPI, so an SDK client
# sends the qualified segment and nothing else.

@router.post("/v1.0/security/runHuntingQuery", dependencies=[Depends(require_graph_write)])
@router.post(
    "/v1.0/security/microsoft.graph.security.runHuntingQuery",
    dependencies=[Depends(require_graph_write)],
)
async def run_hunting_query(
    body: dict = Body(...),
    _: dict = Depends(require_graph_feature("security/runHuntingQuery")),
) -> dict:
    """Execute an advanced hunting query."""
    return sec_queries.run_hunting_query(body=body)


# ── Secure Scores ────────────────────────────────────────────────────────────

@router.get("/v1.0/security/secureScores")
async def list_secure_scores(
    top: int = Query(100, alias="$top", ge=1, le=999),
    skip: int = Query(0, alias="$skip", ge=0),
    _: dict = Depends(require_graph_feature("security/secureScores")),
) -> dict:
    """List secure score snapshots."""
    return sec_queries.list_secure_scores(top=top, skip=skip)


# Microsoft removed the threat-intelligence indicator API from v1.0: the
# name `tiIndicator` appears nowhere in the v1.0 OpenAPI, and beta carries it
# marked `deprecated` with a removal date of 2026-04-10 and the note that the
# legacy Graph Security API stopped returning data on 31 January 2025
# (measured, both documents fetched from msgraph-metadata). mockdr served
# `GET`, `POST` and `DELETE` under `/v1.0/security/tiIndicators`, so a client
# could build against a path the product answers 404 for.


