"""CrowdStrike Falcon Custom IOC API router.

Implements combined search, entity CRUD, and bulk delete for custom
indicators of compromise.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_iocs import commands as ioc_commands
from application.cs_iocs import queries as ioc_queries
from utils.cs_response import query_ids

router = APIRouter(tags=["CrowdStrike IOCs"])


@router.get("/iocs/combined/indicator/v1")
def search_iocs(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query(None),
    after: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Search custom IOCs with an optional FQL filter (combined response).

    gofalcon documents ``after`` here (indicator_combined_v1_parameters.go:
    "provide the 'after' token from the previous response to continue from
    that place in the results"), and the response model carries
    ``meta.pagination.after``. The route did not declare it, so a client
    paging by token was handed the first page again on every call and never
    reached the end.
    """
    return ioc_queries.search_iocs(filter, offset, limit, sort, after)


@router.get("/iocs/entities/indicators/v1")
def get_iocs(
    ids: list[str] = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full IOC entities for the given IDs (repeated ``ids``, or comma-separated)."""
    id_list: list[str] = query_ids(ids)
    return ioc_queries.get_ioc_entities(id_list)


@router.post("/iocs/entities/indicators/v1")
def create_iocs(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Create one or more custom IOC indicators."""
    indicators: list[dict] = body.get("indicators", [])
    return ioc_commands.create_iocs(indicators)


@router.patch("/iocs/entities/indicators/v1")
def update_ioc(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update the custom IOC indicators in ``indicators``.

    ``APIIndicatorUpdateReqsV1`` carries a *list*, each member identified by
    its ``id``; a caller updating three indicators in one call had two of
    them silently ignored while the answer said 200.
    """
    indicators: list[dict] = body.get("indicators", [])
    if not indicators:
        from utils.cs_response import build_cs_error_response
        raise HTTPException(
            status_code=400,
            detail=build_cs_error_response(
                400, "indicators list is required and must not be empty",
            ),
        )
    return ioc_commands.update_iocs(indicators)


@router.delete("/iocs/entities/indicators/v1")
def delete_iocs(
    ids: list[str] = Query(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Delete custom IOCs by IDs (repeated ``ids`` parameters, or comma-separated)."""
    id_list: list[str] = query_ids(ids)
    return ioc_commands.delete_iocs(id_list)
