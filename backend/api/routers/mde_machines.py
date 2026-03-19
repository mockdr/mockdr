"""Microsoft Defender for Endpoint Machines API router.

Implements MDE machine (device) endpoints: listing, detail, sub-resources
(logon users, alerts, software, vulnerabilities, recommendations), and
machine actions (isolate, scan, restrict, etc.).
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.mde_auth import require_mde_auth, require_mde_write
from application.mde_machines import commands as machine_commands
from application.mde_machines import queries as machine_queries
from utils.mde_response import build_mde_error_response

# NOTE: The SoftwareInventoryExport endpoint is on mde_software router.
# The export data download is served from a top-level /_mock route (no auth).

router = APIRouter(tags=["MDE Machines"])


# ── SoftwareInventoryExport (must be before /api/machines/{machine_id}) ───────


@router.get("/api/machines/SoftwareInventoryExport")
def software_inventory_export(
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Export software inventory across all machines (TVM Plan 2).

    Returns download URLs for the exported data.  In the mock, the export
    data is served inline via ``/_mock/mde/software-export-data.json``.
    """
    return machine_queries.get_software_inventory_export()


# ── List / Detail ────────────────────────────────────────────────────────────


@router.get("/api/machines")
def list_machines(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(50, alias="$top", le=1000),
    skip: int = Query(0, alias="$skip"),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all machines with optional OData query parameters."""
    return machine_queries.list_machines(filter_str, top, skip, orderby, select)


@router.get("/api/machines/{machine_id}")
def get_machine(
    machine_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single machine by its machine ID."""
    result = machine_queries.get_machine(machine_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


# ── Sub-resources ────────────────────────────────────────────────────────────


@router.get("/api/machines/{machine_id}/logonusers")
def get_machine_logon_users(
    machine_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get logon users for a specific machine."""
    result = machine_queries.get_machine_logon_users(machine_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.get("/api/machines/{machine_id}/alerts")
def get_machine_alerts(
    machine_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get alerts associated with a specific machine."""
    result = machine_queries.get_machine_alerts(machine_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.get("/api/machines/{machine_id}/software")
def get_machine_software(
    machine_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get software installed on a specific machine."""
    result = machine_queries.get_machine_software(machine_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.get("/api/machines/{machine_id}/vulnerabilities")
def get_machine_vulnerabilities(
    machine_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get vulnerabilities affecting a specific machine."""
    result = machine_queries.get_machine_vulnerabilities(machine_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.get("/api/machines/{machine_id}/recommendations")
def get_machine_recommendations(
    machine_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get security recommendations for a specific machine."""
    result = machine_queries.get_machine_recommendations(machine_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


# ── Machine Actions ──────────────────────────────────────────────────────────


@router.post("/api/machines/{machine_id}/isolate")
def isolate_machine(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Isolate a machine from the network."""
    result = machine_commands.isolate_machine(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/unisolate")
def unisolate_machine(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Release a machine from network isolation."""
    result = machine_commands.unisolate_machine(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/runAntiVirusScan")
def run_av_scan(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Trigger an antivirus scan on a machine."""
    result = machine_commands.run_av_scan(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/restrictCodeExecution")
def restrict_code_execution(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Restrict application execution on a machine."""
    result = machine_commands.restrict_code_execution(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/unrestrictCodeExecution")
def unrestrict_code_execution(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Remove application execution restriction from a machine."""
    result = machine_commands.unrestrict_code_execution(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/collectInvestigationPackage")
def collect_investigation_package(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Collect an investigation package from a machine."""
    result = machine_commands.collect_investigation_package(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/offboard")
def offboard_machine(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Offboard a machine from MDE."""
    result = machine_commands.offboard_machine(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result


@router.post("/api/machines/{machine_id}/runliveresponse")
def run_live_response(
    machine_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_mde_write),
) -> dict:
    """Start a live response session on a machine."""
    result = machine_commands.run_live_response(machine_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response("NotFound", f"Machine {machine_id} not found"),
        )
    return result
