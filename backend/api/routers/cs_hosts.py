"""CrowdStrike Falcon Host API router.

Implements the three CrowdStrike endpoint patterns for host management:
queries (ID-only), entities (full objects), and device actions.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_hosts import commands as host_commands
from application.cs_hosts import queries as host_queries
from utils.cs_response import build_cs_error_response, require_list

router = APIRouter(tags=["CrowdStrike Hosts"])


@router.get("/devices/queries/devices/v1")
def query_hosts(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=1000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return host device IDs matching an optional FQL filter."""
    return host_queries.query_host_ids(filter, offset, limit, sort)


@router.get("/devices/queries/devices-scroll/v1")
def query_hosts_scroll(
    filter: str = Query(None),
    offset: str = Query(None),
    limit: int = Query(5000, ge=1, le=5000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return host device IDs with scroll-based pagination.

    This matches FalconPy's ``query_devices_by_filter_scroll()`` endpoint.
    The ``offset`` is a cursor string (not an integer) that should be passed
    back from ``meta.pagination.offset`` in the previous response.
    """
    return host_queries.query_host_ids_scroll(filter, offset, limit, sort)


@router.get("/devices/combined/devices-hidden/v1")
def list_hidden_devices(
    filter: str = Query(None),  # noqa: A002 - Falcon's own parameter name
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=5000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """List the hosts that ``hide_host`` has taken out of the listings.

    This is the only place a hidden host appears, and having nowhere to look
    is what made hiding look like a deletion.
    """
    return host_queries.list_hidden_hosts(filter, offset, limit, sort)


@router.get("/devices/queries/devices-hidden/v1")
def query_hidden_devices(
    filter: str = Query(None),  # noqa: A002 - Falcon's own parameter name
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=5000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return the ids of the hosts ``hide_host`` has taken out of the listings.

    Falcon publishes every collection twice — the ids under ``queries`` and
    the documents under ``combined`` — and only the second was served here.
    A client following the ids-then-entities pattern, which is how Falcon's
    own SDK reads a collection, met a 404 on the half it starts with.
    """
    return host_queries.query_hidden_host_ids(filter, offset, limit, sort)


@router.post("/devices/entities/devices/v2")
def get_hosts(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full host entities for the given device IDs."""
    ids = require_list(body, "ids")
    return host_queries.get_host_entities(ids)


@router.post("/devices/entities/devices-actions/v2")
def device_action(
    action_name: str = Query(...),
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Execute a device action.

    Falcon documents exactly four for this endpoint — ``contain``,
    ``lift_containment``, ``hide_host`` and ``unhide_host`` — and tagging is
    not among them: it has its own route, ``PATCH
    /devices/entities/devices/tags/v1``. ``unhide_host`` was missing here, so
    a host hidden through this endpoint could never be brought back.

    Args:
        action_name: One of ``contain``, ``lift_containment``, ``hide_host``,
                     ``unhide_host``.
        body:        Dict with an ``ids`` list.
    """
    ids = require_list(body, "ids")
    if not ids:
        raise HTTPException(status_code=400, detail="ids required")

    if action_name == "contain":
        return host_commands.contain_host(ids)
    if action_name == "lift_containment":
        return host_commands.lift_containment(ids)
    if action_name == "hide_host":
        return host_commands.hide_host(ids)
    if action_name == "unhide_host":
        return host_commands.unhide_host(ids)

    raise HTTPException(status_code=400, detail=f"unknown action: {action_name}")


@router.patch("/devices/entities/devices/tags/v1")
def update_device_tags(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Add or remove grouping tags on hosts.

    Tagging is its own route in Falcon — ``DeviceapiUpdateDeviceTagsRequestV1``
    with ``action``, ``device_ids`` and ``tags``, all three required — and
    mockdr served it as an action name on the device-actions endpoint, where
    Falcon has no such action.
    """
    action = str(body.get("action") or "")
    device_ids = require_list(body, "device_ids")
    tags = require_list(body, "tags")
    missing = [
        name for name, value in
        (("action", action), ("device_ids", device_ids), ("tags", tags))
        if not value
    ]
    if missing:
        raise HTTPException(status_code=400, detail=build_cs_error_response(
            400, f"{missing[0]} is required",
        ))
    if action not in ("add", "remove"):
        raise HTTPException(status_code=400, detail=build_cs_error_response(
            400, f"unknown action: {action}",
        ))
    return host_commands.tag_hosts(
        [str(i) for i in device_ids], [str(t) for t in tags], action)
