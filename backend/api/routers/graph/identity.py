"""Microsoft Graph Identity / Conditional Access endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_auth
from application.graph.admin_units import queries as admin_unit_queries
from application.graph.identity import queries as identity_queries
from application.graph.named_locations import queries as named_location_queries

router = APIRouter(tags=["Graph Identity"])


@router.get("/v1.0/identity/conditionalAccess/policies")
async def list_conditional_access_policies(
    filter_str: str = Query(None, alias="$filter"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List Conditional Access policies."""
    return identity_queries.list_ca_policies()


@router.get("/v1.0/identity/conditionalAccess/policies/{policy_id}")
async def get_conditional_access_policy(
    policy_id: str,
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_auth),
) -> dict:
    """Get a single Conditional Access policy by ID."""
    result = identity_queries.get_ca_policy(policy_id)
    if result is None:
        from fastapi import HTTPException

        from utils.graph_response import build_graph_error_response
        raise HTTPException(
            404,
            detail=build_graph_error_response(
                "NotFound",
                f"Policy '{policy_id}' not found",
            ),
        )
    return result


@router.get("/v1.0/identity/conditionalAccess/namedLocations")
async def list_named_locations(
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List named locations (IP and country-based)."""
    return named_location_queries.list_named_locations()


@router.get("/v1.0/directory/administrativeUnits")
async def list_administrative_units(
    _: dict = Depends(require_graph_auth),
) -> dict:
    """List administrative units."""
    return admin_unit_queries.list_admin_units()
