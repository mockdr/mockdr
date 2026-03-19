"""CrowdStrike Falcon Incident API router.

Implements incident queries, entity retrieval, and action endpoints
matching the real CrowdStrike Falcon API path structure.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_incidents import commands as incident_commands
from application.cs_incidents import queries as incident_queries

router = APIRouter(tags=["CrowdStrike Incidents"])


@router.get("/incidents/queries/incidents/v1")
def query_incidents(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return incident IDs matching an optional FQL filter."""
    return incident_queries.query_incident_ids(filter, offset, limit, sort)


@router.post("/incidents/entities/incidents/GET/v1")
def get_incidents(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full incident entities for the given incident IDs."""
    ids: list[str] = body.get("ids", [])
    return incident_queries.get_incident_entities(ids)


@router.post("/incidents/entities/incident-actions/v1")
def incident_action(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Perform an action on one or more incidents.

    Body must contain ``ids`` and ``action_parameters`` (list of
    ``{name, value}`` dicts for status updates, assignment, tagging, etc.).
    """
    ids: list[str] = body.get("ids", [])
    action_parameters: list[dict] = body.get("action_parameters", [])
    return incident_commands.perform_incident_action(ids, action_parameters)
