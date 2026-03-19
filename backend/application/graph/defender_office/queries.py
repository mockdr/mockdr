"""Read-side handlers for Microsoft Graph Defender for Office 365 API."""
from __future__ import annotations

from dataclasses import asdict

from domain.graph.threat_assessment import GraphThreatAssessment
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.attack_simulation_repo import graph_attack_simulation_repo
from repository.graph.threat_assessment_repo import graph_threat_assessment_repo
from utils.dt import utc_now
from utils.graph_response import build_graph_list_response

# ── Attack Simulations ────────────────────────────────────────────────────────

def list_attack_simulations(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return attack simulations with simple pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(s) for s in graph_attack_simulation_repo.list_all()]

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        f"https://graph.microsoft.com/v1.0/security/attackSimulation/simulations?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#security/attackSimulation/simulations",
        next_link=next_link,
    )


# ── Threat Assessments ────────────────────────────────────────────────────────

def list_threat_assessments(
    top: int = 100,
    skip: int = 0,
) -> dict:
    """Return threat assessment requests with simple pagination.

    Args:
        top:  Page size (``$top``).
        skip: Number of records to skip (``$skip``).

    Returns:
        OData list response dict.
    """
    records = [asdict(a) for a in graph_threat_assessment_repo.list_all()]

    total = len(records)
    page = records[skip : skip + top]
    next_link = (
        "https://graph.microsoft.com/v1.0/"
        "informationProtection/"
        f"threatAssessmentRequests?$skip={skip + top}"
        if skip + top < total
        else None
    )
    return build_graph_list_response(
        value=page,
        context="https://graph.microsoft.com/v1.0/$metadata#informationProtection/threatAssessmentRequests",
        next_link=next_link,
    )


def create_threat_assessment(body: dict) -> dict:
    """Create a new threat assessment request from the provided body.

    Args:
        body: Request body dict with contentType, expectedAssessment, category, etc.

    Returns:
        The created threat assessment as a dict.
    """
    assessment = GraphThreatAssessment(
        id=graph_uuid(),
        contentType=body.get("contentType", "mail"),
        expectedAssessment=body.get("expectedAssessment", "block"),
        status="completed",
        category=body.get("category", "phishing"),
        result={
            "resultType": "checkPolicy",
            "message": f"This {body.get('contentType', 'mail')} has been assessed.",
        },
        createdDateTime=utc_now(),
        requestSource=body.get("requestSource", "administrator"),
    )
    graph_threat_assessment_repo.save(assessment)
    return asdict(assessment)
