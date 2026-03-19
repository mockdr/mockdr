"""CrowdStrike Falcon Custom IOC API router.

Implements combined search, entity CRUD, and bulk delete for custom
indicators of compromise.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_iocs import commands as ioc_commands
from application.cs_iocs import queries as ioc_queries

router = APIRouter(tags=["CrowdStrike IOCs"])


@router.get("/iocs/combined/indicator/v1")
def search_iocs(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Search custom IOCs with an optional FQL filter (combined response)."""
    return ioc_queries.search_iocs(filter, offset, limit, sort)


@router.get("/iocs/entities/indicators/v1")
def get_iocs(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full IOC entities for the given comma-separated IDs."""
    id_list: list[str] = [i.strip() for i in ids.split(",") if i.strip()]
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
    """Update an existing custom IOC indicator.

    Body contains ``indicators`` list with a single entry that must include
    the ``id`` field identifying which IOC to update.
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
    indicator = indicators[0]
    ioc_id: str = indicator.get("id", "")
    return ioc_commands.update_ioc(ioc_id, indicator)


@router.delete("/iocs/entities/indicators/v1")
def delete_iocs(
    ids: str = Query(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Delete custom IOCs by comma-separated IDs."""
    id_list: list[str] = [i.strip() for i in ids.split(",") if i.strip()]
    return ioc_commands.delete_iocs(id_list)
