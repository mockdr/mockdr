"""Microsoft Graph Intune App Protection / Mobile Apps endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.graph_auth import require_graph_feature
from application.graph.app_management import queries as app_queries

router = APIRouter(tags=["Graph App Protection"])


@router.get("/v1.0/deviceAppManagement/managedAppPolicies")
async def list_app_protection_policies(
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune app protection (MAM) policies."""
    return app_queries.list_app_protection_policies(top=top, skip=skip)


@router.get("/v1.0/deviceAppManagement/mobileApps")
async def list_mobile_apps(
    filter_str: str = Query(None, alias="$filter"),
    top: int = Query(100, alias="$top", le=999),
    skip: int = Query(0, alias="$skip"),
    select: str = Query(None, alias="$select"),
    _: dict = Depends(require_graph_feature("deviceManagement")),
) -> dict:
    """List Intune mobile apps with OData query parameters."""
    return app_queries.list_mobile_apps(
        filter_str=filter_str, top=top, skip=skip, select=select,
    )
