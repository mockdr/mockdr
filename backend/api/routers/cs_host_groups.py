"""CrowdStrike Falcon Host Group API router.

Implements combined listing, entity CRUD, member management, and group
actions matching the real CrowdStrike Falcon API path structure.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_host_groups import commands as group_commands
from application.cs_host_groups import queries as group_queries
from utils.cs_fql import FqlError, parse_fql
from utils.cs_response import build_cs_error_response, require_list

router = APIRouter(tags=["CrowdStrike Host Groups"])


@router.get("/devices/combined/host-groups/v1")
def list_host_groups(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return host groups with full entities and pagination (combined)."""
    return group_queries.list_host_groups(filter, offset, limit, sort)


@router.get("/devices/queries/host-groups/v1")
def query_host_groups(
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return the IDs of the host groups matching the filter.

    ``QueryHostGroups`` is the ID half of the pair whose ``combined`` half
    this router already served; a client that wants IDs asks here.
    """
    return group_queries.query_host_group_ids(filter, offset, limit, sort)


@router.get("/devices/entities/host-groups/v1")
def get_host_groups(
    ids: str = Query(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return full host group entities for the given comma-separated IDs."""
    id_list: list[str] = [i.strip() for i in ids.split(",") if i.strip()]
    return group_queries.get_host_group_entities(id_list)


@router.post("/devices/entities/host-groups/v1")
def create_host_groups(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Create the host groups in ``resources``.

    ``HostGroupsCreateGroupsReqV1`` requires ``resources``, and each member
    requires ``name`` and ``group_type``.
    """
    resources = require_list(body, "resources")
    if not resources:
        raise HTTPException(
            status_code=400,
            detail=build_cs_error_response(400, "resources is required and must not be empty"),
        )
    for group in resources:
        missing = [f for f in ("name", "group_type") if not (group or {}).get(f)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail=build_cs_error_response(400, f"{missing[0]} is required"),
            )
    return group_commands.create_host_groups(resources)


@router.patch("/devices/entities/host-groups/v1")
def update_host_groups(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Update the host groups in ``resources``.

    ``HostGroupsUpdateGroupsReqV1`` requires ``resources``, and each member
    requires the ``id`` of the group to update.
    """
    resources = require_list(body, "resources")
    if not resources:
        raise HTTPException(
            status_code=400,
            detail=build_cs_error_response(400, "resources is required and must not be empty"),
        )
    for group in resources:
        if not (group or {}).get("id"):
            raise HTTPException(
                status_code=400,
                detail=build_cs_error_response(400, "id is required"),
            )
    return group_commands.update_host_groups(resources)


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

    group_ids = require_list(body, "ids")
    if not group_ids:
        raise HTTPException(status_code=400, detail="ids is required and must not be empty")

    params = require_list(body, "action_parameters")
    host_ids: list[str] = []
    for p in params:
        if p.get("name") != "filter":
            continue
        # The filter is FQL, and this cut it apart by hand: Falcon's own
        # form — `(device_id:['id'])`, parentheses and all — came out as the
        # id with `'])` still attached, so it matched no host and the action
        # answered 200 having done nothing. The mount's own FQL parser reads
        # it now.
        try:
            clauses = parse_fql(str(p.get("value", "")))
        except FqlError:
            continue
        for clause in clauses:
            if clause.field == "device_id":
                host_ids.extend(str(v) for v in clause.values)

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


@router.get("/devices/queries/host-group-members/v1")
def query_host_group_members(
    id: str = Query(...),
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=500),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return the device IDs of a host group's members."""
    return group_queries.query_group_member_ids(id, filter, offset, limit, sort)


@router.get("/devices/combined/host-group-members/v1")
def list_group_members(
    id: str = Query(...),
    filter: str = Query(None),
    offset: int = Query(0),
    limit: int = Query(100, ge=1, le=1000),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return hosts that are members of the specified host group."""
    return group_queries.list_group_members(id, filter, offset, limit)
