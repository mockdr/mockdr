"""Cortex XDR Distributions API router.

All endpoints use POST with ``{"request_data": {...}}`` body wrapper.
Responses use ``{"reply": {...}}`` envelope via ``build_xdr_*`` helpers.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException

from api.xdr_auth import require_xdr_auth, require_xdr_write
from application.xdr_distributions import commands as dist_commands
from application.xdr_distributions import queries as dist_queries
from utils.xdr_response import build_xdr_error

router = APIRouter(tags=["XDR Distributions"])


@router.post("/distributions/get_versions/")
def get_versions(
    body: dict = Body(default={}),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """List available agent versions."""
    return dist_queries.get_versions()


@router.post("/distributions/create/")
def create_distribution(
    body: dict = Body(...),
    _: object = Depends(require_xdr_write),
) -> dict:
    """Create a new agent distribution package."""
    request_data = body.get("request_data", {})
    return dist_commands.create_distribution(request_data)


@router.post("/distributions/get_dist_url/")
def get_distribution_url(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the download URL for a distribution package."""
    request_data = body.get("request_data", {})
    distribution_id = request_data.get("distribution_id", "")
    result = dist_queries.get_distribution_url(distribution_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Distribution {distribution_id} not found"),
        )
    return result


@router.post("/distributions/get_status/")
def get_distribution_status(
    body: dict = Body(...),
    _: object = Depends(require_xdr_auth),
) -> dict:
    """Get the status of a distribution package."""
    request_data = body.get("request_data", {})
    distribution_id = request_data.get("distribution_id", "")
    result = dist_queries.get_distribution_status(distribution_id)
    if result is None:
        raise HTTPException(
            status_code=500,
            detail=build_xdr_error(500, f"Distribution {distribution_id} not found"),
        )
    return result
