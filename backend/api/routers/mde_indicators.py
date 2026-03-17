"""Microsoft Defender for Endpoint Indicators (IoC) API router.

Implements MDE indicator endpoints: listing, detail, create, update
(PATCH), delete, and batch update/delete.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Response

from api.mde_auth import require_mde_auth, require_mde_write
from application.mde_indicators import commands as indicator_commands
from application.mde_indicators import queries as indicator_queries
from utils.mde_response import build_mde_error_response

router = APIRouter(tags=["MDE Indicators"])


@router.get("/api/indicators")
def list_indicators(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all threat indicators with optional OData query parameters."""
    return indicator_queries.list_indicators(filter_str, top, skip, orderby, select)


@router.get("/api/indicators/{indicator_id}")
def get_indicator(
    indicator_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single indicator by its indicator ID."""
    result = indicator_queries.get_indicator(indicator_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Indicator {indicator_id} not found"),
        )
    return result


@router.post("/api/indicators")
def create_indicator(
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Create a new threat indicator."""
    return indicator_commands.create_indicator(body)


@router.patch("/api/indicators/{indicator_id}")
def update_indicator(
    indicator_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Update an existing indicator (PATCH semantics)."""
    result = indicator_commands.update_indicator(indicator_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Indicator {indicator_id} not found"),
        )
    return result


@router.delete("/api/indicators/{indicator_id}")
def delete_indicator(
    indicator_id: str,
    _: dict = Depends(require_mde_write),
) -> Response:
    """Delete an indicator by its ID."""
    deleted = indicator_commands.delete_indicator(indicator_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Indicator {indicator_id} not found"),
        )
    return Response(status_code=204)


@router.post("/api/indicators/batchUpdate")
def batch_update_indicators(
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Batch delete indicators by their values."""
    return indicator_commands.batch_update_indicators(body)
