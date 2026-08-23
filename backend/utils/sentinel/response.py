"""Azure Resource Manager (ARM) response envelope builders for Sentinel.

Every Sentinel resource follows the ARM pattern:
- Single: ``{"id": "...", "name": "...", "type": "...", "properties": {...}}``
- List:   ``{"value": [...], "nextLink": "..."}``
- Error:  ``{"error": {"code": "...", "message": "..."}}``

Sentinel cannot be run locally, so the resources are completed against
fixtures generated from the published 2024-03-01 specification
(``scripts/gen_arm_fixtures.py``): every property the spec declares for a
resource is present, with a type-correct default, and the mock's own values
are deep-merged over it. A client that reads any declared property finds it.
"""
from __future__ import annotations

import json
from functools import cache
from pathlib import Path

_SUB = "00000000-0000-0000-0000-000000000000"
_RG = "mockdr-rg"
_WS = "mockdr-workspace"
_BASE = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{_WS}"
    f"/providers/Microsoft.SecurityInsights"
)

_FIXTURES = Path(__file__).resolve().parents[2] / "infrastructure" / "fixtures" / "sentinel"

#: resource type -> fixture name. Alert rules and templates are polymorphic
#: and resolved by ``kind`` (see ``_fixture_for``).
_FIXTURE_BY_TYPE = {
    "incidents": "incident",
    "incidentComments": "incident_comment",
    "relations": "incident_relation",
    "bookmarks": "bookmark",
    "watchlists": "watchlist",
    "watchlistItems": "watchlist_item",
    "threatIntelligence/main/indicators": "threat_intelligence_indicator",
    "securityAlerts": "security_alert",
}
_RULE_FIXTURE_BY_KIND = {
    "Scheduled": "scheduled_alert_rule",
    "Fusion": "fusion_alert_rule",
    "MicrosoftSecurityIncidentCreation": "ms_security_incident_creation_alert_rule",
}
#: The eight connector kinds the stable 2024-03-01 spec declares, plus the
#: codeless ``GenericUI`` kind, whose shape only the preview spec declares
#: (ARM returns such connectors under any api-version).
_CONNECTOR_FIXTURE_BY_KIND = {
    "GenericUI": "generic_ui_data_connector",
    "AzureActiveDirectory": "aad_data_connector",
    "AzureAdvancedThreatProtection": "aatp_data_connector",
    "AzureSecurityCenter": "asc_data_connector",
    "AmazonWebServicesCloudTrail": "aws_cloud_trail_data_connector",
    "MicrosoftCloudAppSecurity": "mcas_data_connector",
    "MicrosoftDefenderAdvancedThreatProtection": "mdatp_data_connector",
    "ThreatIntelligence": "ti_data_connector",
    "Office365": "office_data_connector",
}

#: ARM ``systemData`` as the platform stamps it on every resource.
_SYSTEM_DATA = {
    "createdBy": "mockdr@localhost",
    "createdByType": "User",
    "createdAt": "2024-01-01T00:00:00.0000000Z",
    "lastModifiedBy": "mockdr@localhost",
    "lastModifiedByType": "User",
    "lastModifiedAt": "2024-01-01T00:00:00.0000000Z",
}


@cache
def _load_fixture(name: str) -> dict:
    path = _FIXTURES / f"{name}.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, dict) else {}


def _fixture_for(resource_type: str, kind: str) -> dict:
    if resource_type == "alertRules":
        name = _RULE_FIXTURE_BY_KIND.get(kind, "scheduled_alert_rule")
    elif resource_type == "alertRuleTemplates":
        name = "scheduled_alert_rule_template"
    elif resource_type == "dataConnectors":
        name = _CONNECTOR_FIXTURE_BY_KIND.get(kind, "")
    else:
        name = _FIXTURE_BY_TYPE.get(resource_type, "")
    return _load_fixture(name) if name else {}


def fixture_properties(resource_type: str, kind: str = "") -> dict:
    """A fresh copy of the spec-declared property bag for a resource, or ``{}``."""
    fresh = _blank(_fixture_for(resource_type, kind).get("properties") or {})
    return fresh if isinstance(fresh, dict) else {}


def deep_complete(defaults: dict, actual: dict) -> dict:
    """Return ``actual`` with every key of ``defaults`` it lacks filled in.

    Nested dicts recurse so a partially built sub-object keeps its values
    and gains the declared siblings; lists and scalars from ``actual`` win
    untouched. ``defaults`` is never mutated.
    """
    out = {k: _blank(v) for k, v in defaults.items()}
    for key, value in actual.items():
        template = defaults.get(key)
        if isinstance(value, dict) and isinstance(template, dict):
            out[key] = deep_complete(template, value)
        else:
            out[key] = value
    return out


def _blank(default: object) -> object:
    """A fresh value for a missing key: lists and objects rebuilt, scalars shared."""
    if isinstance(default, list):
        return [_blank(i) for i in default]
    if isinstance(default, dict):
        return {k: _blank(v) for k, v in default.items()}
    return default


def build_arm_resource(
    resource_type: str,
    name: str,
    properties: dict,
    *,
    etag: str = "",
    kind: str = "",
) -> dict:
    """Build a single ARM resource envelope, completed against the spec.

    Args:
        resource_type: e.g. ``"incidents"``, ``"alertRules"``.
        name:          Resource name / ID.
        properties:    The resource-specific property bag.
        etag:          Optional ETag value.
        kind:          Polymorphic discriminator (alert rules, templates,
                       data connectors); emitted at the top level as ARM does.

    Returns:
        ARM resource dict.
    """
    fixture = _fixture_for(resource_type, kind)
    defaults = {k: v for k, v in fixture.items() if k not in ("id", "name", "type", "etag", "kind")}
    result: dict = {
        "id": f"{_BASE}/{resource_type}/{name}",
        "name": name,
        "type": f"Microsoft.SecurityInsights/{resource_type}",
    }
    if kind:
        result["kind"] = kind
    if etag:
        result["etag"] = f'"{etag}"'
    result["properties"] = properties
    completed = deep_complete(defaults, result)
    if "systemData" in fixture:
        completed["systemData"] = deep_complete(_SYSTEM_DATA, completed.get("systemData") or {})
    return completed


def build_arm_list(
    items: list[dict],
    *,
    next_link: str = "",
) -> dict:
    """Build an ARM list response envelope.

    Args:
        items:     List of ARM resource dicts.
        next_link: Optional pagination URL.

    Returns:
        ARM list response dict.
    """
    result: dict = {"value": items}
    if next_link:
        result["nextLink"] = next_link
    return result


def build_arm_error(code: str, message: str) -> dict:
    """Build an ARM error response body.

    Args:
        code:    Error code string.
        message: Human-readable error message.

    Returns:
        ARM error envelope dict.
    """
    return {"error": {"code": code, "message": message}}



def build_log_analytics_response(
    columns: list[dict[str, str]],
    rows: list[list],
) -> dict:
    """Build a Log Analytics query response.

    Args:
        columns: List of ``{"name": "...", "type": "..."}`` dicts.
        rows:    List of row arrays.

    Returns:
        Log Analytics response dict.
    """
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": columns,
            "rows": rows,
        }],
    }
