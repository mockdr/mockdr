"""Microsoft Defender for Endpoint Vulnerabilities (TVM) API router.

Implements MDE vulnerability endpoints: listing, detail, and
machine references.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from api.mde_auth import require_mde_auth
from application.mde_vulnerabilities import queries as vuln_queries
from utils.mde_filterable import refuse_unfilterable
from utils.mde_response import build_mde_error_response

router = APIRouter(tags=["MDE Vulnerabilities"])


@router.get("/api/vulnerabilities")
def list_vulnerabilities(
    filter_str: str = Query(None, alias="$filter"),
    # "$top with max value of 8,000" (get-all-vulnerabilities on learn.microsoft.com/en-us/
    # defender-endpoint/api/); the cap was 1000. No default page size is
    # documented, so the default stays 50.
    top: int = Query(50, alias="$top", ge=1, le=8000),
    skip: int = Query(0, alias="$skip", ge=0),
    orderby: str = Query(None, alias="$orderby"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """List all vulnerabilities with optional OData query parameters."""
    refuse_unfilterable(filter_str, "vulnerabilities")
    return vuln_queries.list_vulnerabilities(filter_str, top, skip, orderby, select)


@router.get("/api/vulnerabilities/{vuln_id}")
def get_vulnerability(
    vuln_id: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get a single vulnerability by its CVE ID."""
    result = vuln_queries.get_vulnerability(vuln_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response(
                "ResourceNotFound",
                f"Vulnerability {vuln_id} not found",
            ),
        )
    return result


@router.get("/api/vulnerabilities/{vuln_id}/machineReferences")
def get_vulnerability_machine_references(
    vuln_id: str,
    top: int = Query(50, alias="$top", ge=1, le=1000),
    skip: int = Query(0, alias="$skip", ge=0),
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get machines affected by a specific vulnerability."""
    result = vuln_queries.get_vulnerability_machine_references(vuln_id, top, skip)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_mde_error_response(
                "ResourceNotFound",
                f"Vulnerability {vuln_id} not found",
            ),
        )
    return result
