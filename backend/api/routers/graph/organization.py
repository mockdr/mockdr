"""Microsoft Graph Organization endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.graph_auth import require_graph_auth
from application.graph.organization import queries as org_queries

router = APIRouter(tags=["Graph Organization"])


@router.get("/v1.0/organization")
async def list_organization(
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Return the tenant organization record.

    Always returns a list with a single organization entry, matching
    the real Microsoft Graph API behaviour.
    """
    return org_queries.list_organization()
