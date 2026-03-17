"""Microsoft Defender for Endpoint Investigations API router.

Implements MDE automated investigation endpoints: listing, detail,
and evidence collection.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.mde_auth import require_mde_auth, require_mde_write
from application.mde_investigations import commands as investigation_commands
from application.mde_investigations import queries as investigation_queries
from utils.mde_response import build_mde_error_response

router = APIRouter(tags=["MDE Investigations"])


@router.get("/api/investigations")
def list_investigations(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all automated investigations with optional OData query parameters."""
    return investigation_queries.list_investigations(filter_str, top, skip, orderby)


@router.get("/api/investigations/{investigation_id}")
def get_investigation(
    investigation_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single investigation by its investigation ID."""
    result = investigation_queries.get_investigation(investigation_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response(
                "NotFound", f"Investigation {investigation_id} not found",
            ),
        )
    return result


@router.post("/api/investigations/{investigation_id}/collect")
def collect_investigation(
    investigation_id: str,
    _: dict = Depends(require_mde_write),
) -> dict:
    """Trigger evidence collection for an investigation."""
    result = investigation_commands.collect_investigation(investigation_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response(
                "NotFound", f"Investigation {investigation_id} not found",
            ),
        )
    return result
