"""Microsoft Defender for Endpoint Machine Actions API router.

Implements MDE machine action endpoints: listing, detail, and
package URI retrieval for investigation packages.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.mde_auth import require_mde_auth
from application.mde_machine_actions import queries as action_queries
from utils.mde_response import build_mde_error_response

router = APIRouter(tags=["MDE Machine Actions"])


@router.get("/api/machineactions")
def list_machine_actions(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all machine actions with optional OData query parameters."""
    return action_queries.list_machine_actions(filter_str, top, skip, orderby)


@router.get("/api/machineactions/{action_id}")
def get_machine_action(
    action_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single machine action by its action ID."""
    result = action_queries.get_machine_action(action_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"MachineAction {action_id} not found"),
        )
    return result


@router.get("/api/machineactions/{action_id}/getPackageUri")
def get_package_uri(
    action_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get the download URI for a collected investigation package."""
    result = action_queries.get_package_uri(action_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"MachineAction {action_id} not found"),
        )
    return result
