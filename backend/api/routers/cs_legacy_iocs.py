"""CrowdStrike Falcon Legacy IOC API router.

Implements the deprecated ``/indicators/`` endpoints that older XSOAR
integrations still use alongside the modern ``/iocs/`` endpoints.
Maps directly to the same ``cs_iocs`` store — same data, different paths.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_iocs import commands as ioc_commands
from application.cs_iocs import queries as ioc_queries

router = APIRouter(tags=["CrowdStrike Legacy IOCs"])


@router.get("/indicators/queries/iocs/v1")
def query_legacy_ioc_ids(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Query legacy IOC IDs with optional FQL filter."""
    return ioc_queries.query_ioc_ids(filter, offset, limit, sort)


@router.get("/indicators/entities/iocs/v1")
def get_legacy_ioc_entities(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full legacy IOC entities by comma-separated IDs."""
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    return ioc_queries.get_ioc_entities(id_list)


@router.post("/indicators/entities/iocs/v1")
def create_legacy_ioc(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Upload/create a legacy IOC."""
    indicators = body.get("indicators", [body]) if "indicators" in body else [body]
    return ioc_commands.create_iocs(indicators)


@router.patch("/indicators/entities/iocs/v1")
def update_legacy_ioc(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update a legacy IOC."""
    ioc_id = body.get("id", "")
    return ioc_commands.update_ioc(ioc_id, body)


@router.delete("/indicators/entities/iocs/v1")
def delete_legacy_ioc(
    ids: str = Query(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Delete legacy IOCs by comma-separated IDs."""
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    return ioc_commands.delete_iocs(id_list)


@router.get("/indicators/aggregates/devices-count/v1")
def device_count_for_ioc(
    type: str = Query(...),
    value: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return the count of devices that have seen the given IOC.

    Mock always returns a deterministic count based on the IOC value.
    """
    return ioc_queries.device_count_for_ioc(type, value)


@router.get("/indicators/queries/processes/v1")
def processes_ran_on(
    type: str = Query(...),
    value: str = Query(...),
    device_id: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return process IDs that accessed the given IOC.

    Mock returns a small deterministic set of fake process IDs.
    """
    return ioc_queries.processes_ran_on(type, value, device_id)
