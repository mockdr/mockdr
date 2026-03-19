"""CrowdStrike Falcon Quarantine API router.

Implements quarantined-file query and action endpoints used by XSOAR
for managing files quarantined by the Falcon sensor.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_quarantine import commands as quarantine_commands
from application.cs_quarantine import queries as quarantine_queries

router = APIRouter(tags=["CrowdStrike Quarantine"])


@router.get("/quarantine/queries/quarantined-files/v1")
def query_quarantined_files(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Query quarantined file IDs with optional FQL filter."""
    return quarantine_queries.query_quarantined_file_ids(filter, offset, limit, sort)


@router.get("/quarantine/entities/quarantined-files/v1")
def get_quarantined_file_entities(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full quarantined file entities by comma-separated IDs."""
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    return quarantine_queries.get_quarantined_file_entities(id_list)


@router.patch("/quarantine/entities/quarantined-files/v1")
def action_quarantined_files(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Apply an action to quarantined files.

    Body: ``{"ids": [...], "action": "release|delete|unquarantine"}``.
    """
    ids = body.get("ids", [])
    action = body.get("action", "release")
    return quarantine_commands.action_quarantined_files(ids, action)
