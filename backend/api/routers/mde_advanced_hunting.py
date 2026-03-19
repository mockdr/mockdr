"""Microsoft Defender for Endpoint Advanced Hunting API router.

Implements the MDE advanced hunting endpoint that accepts KQL queries
and returns tabular results.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends

from api.mde_auth import require_mde_auth
from application.mde_advanced_hunting import queries as hunting_queries

router = APIRouter(tags=["MDE Advanced Hunting"])


@router.post("/api/advancedqueries/run")
def run_advanced_query(
    body: dict = Body(...),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Execute an advanced hunting KQL query and return results."""
    return hunting_queries.run_query(body)
