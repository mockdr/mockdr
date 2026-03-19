"""Microsoft Graph Defender for Office 365 API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.graph_auth import require_graph_auth, require_graph_feature
from application.graph.defender_office import queries as defender_queries

router = APIRouter(tags=["Graph Defender for Office 365"])


# ── Attack Simulations ────────────────────────────────────────────────────────

@router.get("/v1.0/security/attackSimulation/simulations")
async def list_attack_simulations(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("attackSimulation")),
) -> dict:
    """List attack simulations."""
    return defender_queries.list_attack_simulations(top=top, skip=skip)


# ── Threat Assessments ────────────────────────────────────────────────────────

@router.get("/v1.0/informationProtection/threatAssessmentRequests")
async def list_threat_assessments(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List threat assessment requests."""
    return defender_queries.list_threat_assessments(top=top, skip=skip)


@router.post("/v1.0/informationProtection/threatAssessmentRequests")
async def create_threat_assessment(
    body: dict = Body(...),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Create a new threat assessment request."""
    return defender_queries.create_threat_assessment(body=body)
