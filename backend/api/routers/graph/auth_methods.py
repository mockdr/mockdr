"""Microsoft Graph Authentication Methods reports endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.auth_methods import queries as auth_methods_queries

router = APIRouter(tags=["Graph Auth Methods"])


@router.get("/beta/reports/authenticationMethods/userRegistrationDetails")
async def list_user_registration_details(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List MFA registration details for all users."""
    return auth_methods_queries.list_registration_details(
        filter_str, top, skip,
    )
