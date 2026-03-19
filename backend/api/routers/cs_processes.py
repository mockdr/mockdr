"""CrowdStrike Falcon Process Analysis API router.

Implements ``/processes/entities/processes/v1`` used by XSOAR to retrieve
process details from detected activity.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.cs_auth import require_cs_auth
from application.cs_processes import queries as process_queries

router = APIRouter(tags=["CrowdStrike Processes"])


@router.get("/processes/entities/processes/v1")
def get_process_entities(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return process entities by comma-separated process IDs."""
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    return process_queries.get_process_entities(id_list)
