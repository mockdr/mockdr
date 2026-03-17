"""Sentinel Alert Rules router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import alert_rules as rule_cmds
from application.sentinel.queries import alert_rules as rule_queries
from utils.sentinel.response import build_arm_error

router = APIRouter(tags=["Sentinel Alert Rules"])

_WS = (
    "/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
    "/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
    "/providers/Microsoft.SecurityInsights"
)


@router.get(_WS + "/alertRules")
def list_alert_rules(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List all alert rules."""
    return rule_queries.list_alert_rules()


@router.get(_WS + "/alertRules/{rule_id}")
def get_alert_rule(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    rule_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Get a single alert rule."""
    result = rule_queries.get_alert_rule(rule_id)
    if not result:
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Alert rule '{rule_id}' not found"),
        )
    return result


@router.put(_WS + "/alertRules/{rule_id}")
async def create_or_update_alert_rule(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    rule_id: str,
    request: Request,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Create or update an alert rule."""
    body = await request.json()
    kind = body.get("kind", "Scheduled")
    properties = body.get("properties", {})
    properties["kind"] = kind
    rule_cmds.create_or_update_rule(rule_id, properties)
    return rule_queries.get_alert_rule(rule_id) or {}


@router.delete(_WS + "/alertRules/{rule_id}")
def delete_alert_rule(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    rule_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """Delete an alert rule."""
    if not rule_cmds.delete_rule(rule_id):
        raise HTTPException(
            status_code=404,
            detail=build_arm_error("NotFound", f"Alert rule '{rule_id}' not found"),
        )
    return {}


@router.get(_WS + "/alertRuleTemplates")
def list_alert_rule_templates(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List alert rule templates (stub)."""
    return {"value": []}
