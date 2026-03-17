"""CrowdStrike Falcon Host API router.

Implements the three CrowdStrike endpoint patterns for host management:
queries (ID-only), entities (full objects), and device actions.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_hosts import commands as host_commands
from application.cs_hosts import queries as host_queries

router = APIRouter(tags=["CrowdStrike Hosts"])


@router.get("/devices/queries/devices/v1")
def query_hosts(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=1000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return host device IDs matching an optional FQL filter."""
    return host_queries.query_host_ids(filter, offset, limit, sort)


@router.get("/devices/queries/devices-scroll/v1")
def query_hosts_scroll(
    filter: str = Query(None),
    offset: str = Query(None),
    limit: int = Query(5000, le=5000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return host device IDs with scroll-based pagination.

    This matches FalconPy's ``query_devices_by_filter_scroll()`` endpoint.
    The ``offset`` is a cursor string (not an integer) that should be passed
    back from ``meta.pagination.offset`` in the previous response.
    """
    return host_queries.query_host_ids_scroll(filter, offset, limit, sort)


@router.post("/devices/entities/devices/v2")
def get_hosts(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full host entities for the given device IDs."""
    ids: list[str] = body.get("ids", [])
    return host_queries.get_host_entities(ids)


@router.post("/devices/entities/devices-actions/v2")
def device_action(
    action_name: str = Query(...),
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Execute a device action (contain, lift_containment, hide_host, tag).

    Args:
        action_name: One of ``contain``, ``lift_containment``, ``hide_host``,
                     ``add-hosts``, ``remove-hosts``.
        body:        Dict with ``ids`` list and optional ``action_parameters``.
    """
    ids: list[str] = body.get("ids", [])
    if not ids:
        raise HTTPException(status_code=400, detail="ids required")

    if action_name == "contain":
        return host_commands.contain_host(ids)
    if action_name == "lift_containment":
        return host_commands.lift_containment(ids)
    if action_name == "hide_host":
        return host_commands.hide_host(ids)
    if action_name in ("add-hosts", "remove-hosts"):
        params = body.get("action_parameters", [])
        tags: list[str] = []
        for p in params:
            if p.get("name") == "FalconGroupingTags":
                tags = [t.strip() for t in p.get("value", "").split(",") if t.strip()]
        action = "add" if action_name == "add-hosts" else "remove"
        return host_commands.tag_hosts(ids, tags, action)

    raise HTTPException(status_code=400, detail=f"unknown action: {action_name}")
