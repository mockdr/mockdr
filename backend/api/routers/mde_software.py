"""Microsoft Defender for Endpoint Software (TVM) API router.

Implements MDE software inventory endpoints: listing, detail, and
machine references.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.mde_auth import require_mde_auth
from application.mde_software import queries as software_queries
from utils.mde_response import build_mde_error_response

router = APIRouter(tags=["MDE Software"])


@router.get("/api/software")
def list_software(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all software in the TVM inventory with optional OData query parameters."""
    return software_queries.list_software(filter_str, top, skip, orderby, select)


@router.get("/api/software/{software_id}")
def get_software(
    software_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single software entry by its software ID."""
    result = software_queries.get_software(software_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Software {software_id} not found"),
        )
    return result


@router.get("/api/software/{software_id}/machineReferences")
def get_software_machine_references(
    software_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get machines that have a specific software installed."""
    result = software_queries.get_software_machine_references(software_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Software {software_id} not found"),
        )
    return result
