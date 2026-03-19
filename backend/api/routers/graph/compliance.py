"""Microsoft Graph Compliance Policies and Device Configurations endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_feature
from application.graph.compliance import queries as compliance_queries

router = APIRouter(tags=["Graph Compliance"])


@router.get("/v1.0/deviceManagement/deviceCompliancePolicies")
async def list_compliance_policies(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune device compliance policies with OData query parameters."""
    return compliance_queries.list_compliance_policies(
        filter_str=filter_str, top=top, skip=skip, select=select,
    )


@router.get("/v1.0/deviceManagement/deviceConfigurations")
async def list_device_configurations(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune device configuration profiles with OData query parameters."""
    return compliance_queries.list_device_configurations(
        filter_str=filter_str, top=top, skip=skip, select=select,
    )
