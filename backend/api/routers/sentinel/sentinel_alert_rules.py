"""Sentinel Alert Rules router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.sentinel_auth import require_sentinel_auth
from application.sentinel.commands import alert_rules as rule_cmds
from application.sentinel.queries import alert_rules as rule_queries
from utils.sentinel.response import build_arm_error, build_arm_list, build_arm_resource
from utils.vendor_errors import build_vendor_error

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
            detail=build_arm_error("ResourceNotFound", f"Alert rule '{rule_id}' not found"),
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
    if not isinstance(body, dict):
        # A JSON null or array reached `.get` on the wrong type and 500ed.
        raise HTTPException(
            status_code=400,
            detail=build_vendor_error("sentinel", 400, "Request body must be a JSON object"),
        )
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
            detail=build_arm_error("ResourceNotFound", f"Alert rule '{rule_id}' not found"),
        )
    return {}


#: Built-in Scheduled templates, as the content hub ships them. A real
#: workspace lists hundreds; a client that pages or filters sees the same
#: shape here. This used to be an empty list.
_TEMPLATES: list[tuple[str, str, str, str, list[str]]] = [
    (
        "0dd422ee-d7a3-4b10-8e1c-4e2bcd6d2f2a",
        "Brute force attack against user credentials",
        "Identifies evidence of brute force activity against a user.",
        "SigninLogs | where ResultType == 50126 | summarize count() by UserPrincipalName",
        ["CredentialAccess"],
    ),
    (
        "b3b5c7e2-5d1a-4f2a-9c1d-1b2d3e4f5a60",
        "Rare RDP connections",
        "Identifies RDP connections from a source not seen in the last 14 days.",
        "SecurityEvent | where EventID == 4624 and LogonType == 10",
        ["LateralMovement"],
    ),
    (
        "e1ce0f6a-2f3b-4d3e-8a5f-6c7d8e9f0a11",
        "Known malicious IP in network traffic",
        "Matches outbound connections against the threat-intelligence indicators.",
        "CommonSecurityLog | join kind=inner ThreatIntelligenceIndicator"
        " on $left.DestinationIP == $right.NetworkIP",
        ["CommandAndControl"],
    ),
]


def _template_to_arm(
    template_id: str,
    name: str,
    description: str,
    query: str,
    tactics: list[str],
) -> dict:
    return build_arm_resource(
        "alertRuleTemplates",
        template_id,
        {
            "displayName": name,
            "description": description,
            "query": query,
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "severity": "Medium",
            "tactics": tactics,
            "techniques": [],
            "status": "Available",
            "alertRulesCreatedByTemplateCount": 0,
            "createdDateUTC": "2024-01-01T00:00:00Z",
            "lastUpdatedDateUTC": "2024-01-01T00:00:00Z",
            "requiredDataConnectors": [],
            "version": "1.0.0",
        },
        kind="Scheduled",
    )


@router.get(_WS + "/alertRuleTemplates")
def list_alert_rule_templates(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> dict:
    """List the alert rule templates."""
    return build_arm_list([_template_to_arm(*t) for t in _TEMPLATES])


@router.get(_WS + "/alertRuleTemplates/{template_id}", response_model=None)
def get_alert_rule_template(
    subscription_id: str,
    resource_group: str,
    workspace: str,
    template_id: str,
    api_version: str = Query(default="2024-03-01", alias="api-version"),
    _auth: dict = Depends(require_sentinel_auth),
) -> JSONResponse | dict:
    """Get one alert rule template, 404 as ARM phrases it."""
    for t in _TEMPLATES:
        if t[0] == template_id:
            return _template_to_arm(*t)
    return JSONResponse(
        status_code=404,
        content=build_arm_error("NotFound", f"Resource '{template_id}' does not exist"),
    )
