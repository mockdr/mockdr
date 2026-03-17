"""CrowdStrike Falcon Host Group API router.

Implements combined listing, entity CRUD, member management, and group
actions matching the real CrowdStrike Falcon API path structure.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_host_groups import commands as group_commands
from application.cs_host_groups import queries as group_queries

router = APIRouter(tags=["CrowdStrike Host Groups"])


@router.get("/devices/combined/host-groups/v1")
def list_host_groups(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return host groups with full entities and pagination (combined)."""
    return group_queries.list_host_groups(filter, offset, limit, sort)


@router.get("/devices/entities/host-groups/v1")
def get_host_groups(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full host group entities for the given comma-separated IDs."""
    id_list: list[str] = [i.strip() for i in ids.split(",") if i.strip()]
    return group_queries.get_host_group_entities(id_list)


@router.post("/devices/entities/host-groups/v1")
def create_host_group(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Create a new host group."""
    return group_commands.create_host_group(body)


@router.patch("/devices/entities/host-groups/v1")
def update_host_group(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update an existing host group (``id`` field required in body)."""
    return group_commands.update_host_group(body)


@router.delete("/devices/entities/host-groups/v1")
def delete_host_groups(
    ids: str = Query(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Delete host groups by comma-separated IDs."""
    id_list: list[str] = [i.strip() for i in ids.split(",") if i.strip()]
    return group_commands.delete_host_groups(id_list)


@router.post("/devices/entities/host-group-actions/v1")
def group_action(
    action_name: str = Query(...),
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Add or remove hosts from a host group.

    Args:
        action_name: ``add-hosts`` or ``remove-hosts``.
        body:        Dict with ``ids`` (host group IDs) and
                     ``action_parameters`` containing a ``filter`` with
                     device IDs.
    """
    if action_name not in ("add-hosts", "remove-hosts"):
        raise HTTPException(status_code=400, detail=f"unknown action: {action_name}")

    group_ids: list[str] = body.get("ids", [])
    if not group_ids:
        raise HTTPException(status_code=400, detail="ids is required and must not be empty")

    params: list[dict] = body.get("action_parameters", [])
    host_ids: list[str] = []
    for p in params:
        if p.get("name") == "filter":
            raw_filter: str = p.get("value", "")
            # Parse "device_id:['id1','id2']" style filter values.
            if "device_id:" in raw_filter:
                inner = raw_filter.split("device_id:", 1)[1]
                inner = inner.strip("[] '\"")
                host_ids = [h.strip().strip("'\"") for h in inner.split(",") if h.strip()]

    results: list[dict] = []
    for gid in group_ids:
        result = group_commands.manage_group_members(gid, action_name, host_ids)
        results.append(result)
    # Aggregate resources from all group operations into a single response.
    all_resources: list[dict] = []
    for r in results:
        all_resources.extend(r.get("resources", []))
    combined = results[0].copy() if results else {}
    combined["resources"] = all_resources
    return combined


@router.get("/devices/combined/host-group-members/v1")
def list_group_members(
    id: str = Query(...),
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, le=1000),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return hosts that are members of the specified host group."""
    return group_queries.list_group_members(id, filter, offset, limit)
