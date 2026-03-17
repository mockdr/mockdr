"""Sentinel Threat Intelligence router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import threat_intel as ti_cmds
from application.sentinel.queries import threat_intel as ti_queries
from utils.sentinel.response import build_arm_error

router = APIRouter(tags=["Sentinel Threat Intelligence"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


# ── List indicators ──────────────────────────────────────────────────────


@router.get(_WS + "/threatIntelligence/main/indicators")
def list_indicators(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    top: int = Query(default=None, alias="$top"),
    skip_token: str = Query(default=None, alias="$skipToken"),
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List threat intelligence indicators."""
    return ti_queries.list_indicators(top=min(top or 50, 1000), skip_token=skip_token or "")


# ── Bulk operations (must be before {name} route) ────────────────────────


@router.post(_WS + "/threatIntelligence/main/indicators/appendTags")
async def append_tags(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Append tags to indicators."""
    body = await request.json()
    indicator_names = body.get("indicatorNames", [])
    tags = body.get("tags", [])
    count = ti_cmds.append_tags(indicator_names, tags)
    return {"updated": count}


@router.post(_WS + "/threatIntelligence/main/indicators/replaceTags")
async def replace_tags(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Replace tags on indicators."""
    body = await request.json()
    indicator_names = body.get("indicatorNames", [])
    tags = body.get("tags", [])
    count = ti_cmds.replace_tags(indicator_names, tags)
    return {"updated": count}


# ── Single indicator CRUD ────────────────────────────────────────────────


@router.get(_WS + "/threatIntelligence/main/indicators/{name}")
def get_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single threat intelligence indicator."""
    result = ti_queries.get_indicator(name)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Indicator '{name}' not found"),
        )
    return result


@router.put(_WS + "/threatIntelligence/main/indicators/{name}")
async def create_or_update_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update a threat intelligence indicator."""
    body = await request.json()
    properties = body.get("properties", {})
    ti_cmds.create_or_update_indicator(name, properties)
    return ti_queries.get_indicator(name) or {}


@router.delete(_WS + "/threatIntelligence/main/indicators/{name}")
def delete_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    name: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete a threat intelligence indicator."""
    if not ti_cmds.delete_indicator(name):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Indicator '{name}' not found"),
        )
    return {}


# ── Create with auto-name ────────────────────────────────────────────────


@router.post(_WS + "/threatIntelligence/main/createIndicator")
async def create_indicator(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create a threat intelligence indicator with auto-generated name."""
    body = await request.json()
    properties = body.get("properties", {})
    indicator = ti_cmds.create_indicator(properties)
    result = ti_queries.get_indicator(indicator.name)
    return result or {}


# ── Query / Metrics ──────────────────────────────────────────────────────


@router.post(_WS + "/threatIntelligence/main/queryIndicators")
async def query_indicators(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Query threat intelligence indicators."""
    body = await request.json()
    return ti_queries.query_indicators(
        keywords=body.get("keywords"),
        pattern_types=body.get("patternTypes"),
        sources=body.get("sources"),
    )


@router.post(_WS + "/threatIntelligence/main/metrics")
def get_metrics(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get threat intelligence metrics."""
    return ti_queries.get_metrics()
