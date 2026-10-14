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
import re
from contextvars import ContextVar, Token
from functools import cache
from pathlib import Path

from starlette.responses import JSONResponse, Response

_SUB = "00000000-0000-0000-0000-000000000000"
_RG = "mockdr-rg"
_WS = "mockdr-workspace"
_BASE = (
    f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
    f"/providers/Microsoft.OperationalInsights/workspaces/{_WS}"
    f"/providers/Microsoft.SecurityInsights"
)

#: The workspace a request addressed, as its path spelled it. ARM answers a
#: resource's `id` under the subscription, resource group and workspace the
#: request named; the mock answered every id under its own default workspace,
#: so a client addressing `/subscriptions/<its own>/resourceGroups/<its own>`
#: was handed ids that named someone else's, and a client that follows an
#: `id` back went to a path it never used. ADR-012 keeps accepting any
#: workspace — the mock has one, and serves it under every name — so the id
#: echoes the one asked for. Outside a request (seeding) the default holds.
_REQUEST_BASE: ContextVar[str] = ContextVar("sentinel_arm_base", default=_BASE)

_WORKSPACE_PATH = re.compile(
    r"^/sentinel(/subscriptions/[^/]+/resourceGroups/[^/]+"
    r"/providers/Microsoft\.OperationalInsights/workspaces/[^/]+"
    r"/providers/Microsoft\.SecurityInsights)(?:/|$)",
    re.IGNORECASE,
)


def address_workspace(path: str) -> Token[str] | None:
    """Make ids built for this request name the workspace its path names.

    Returns:
        The token to reset the context with, or None when the path names no
        workspace.
    """
    match = _WORKSPACE_PATH.match(path)
    return _REQUEST_BASE.set(match.group(1)) if match else None


def release_workspace(token: Token[str] | None) -> None:
    """Undo :func:`address_workspace` once the request is answered."""
    if token is not None:
        _REQUEST_BASE.reset(token)


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


def _system_data(properties: dict) -> dict:
    """ARM's ``systemData`` for a resource, dated by the resource's own clock.

    An incident says when it was created and last modified
    (``createdTimeUtc``, ``lastModifiedTimeUtc``); its systemData saying
    otherwise would be a second, contradicting answer. A resource without
    those keeps the fixed default.
    """
    data = dict(_SYSTEM_DATA)
    created = properties.get("createdTimeUtc")
    modified = properties.get("lastModifiedTimeUtc") or properties.get("lastModifiedUtc")
    if isinstance(created, str) and created:
        data["createdAt"] = created
        data["lastModifiedAt"] = created
    if isinstance(modified, str) and modified:
        data["lastModifiedAt"] = modified
    return data


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
    out: dict = {}
    for key, template in defaults.items():
        if key not in actual:
            # Only a key the resource lacks needs a default built for it.
            out[key] = _blank(template)
            continue
        value = actual[key]
        if type(value) is dict and type(template) is dict:
            out[key] = deep_complete(template, value)
        else:
            out[key] = value
    for key, value in actual.items():
        if key not in defaults:
            out[key] = value
    return out


def _blank(default: object) -> object:
    """A fresh value for a missing key: lists and objects rebuilt, scalars shared."""
    if isinstance(default, list):
        return [_blank(i) for i in default]
    if isinstance(default, dict):
        return {k: _blank(v) for k, v in default.items()}
    return default


def arm_id(resource_type: str, name: str) -> str:
    """The fully qualified ARM id of a workspace resource, under the workspace addressed."""
    return f"{_REQUEST_BASE.get()}/{resource_type}/{name}"


def build_arm_resource(
    resource_type: str,
    name: str,
    properties: dict,
    *,
    etag: str = "",
    kind: str = "",
    path: str = "",
    type_name: str = "",
) -> dict:
    """Build a single ARM resource envelope, completed against the spec.

    Args:
        resource_type: e.g. ``"incidents"``, ``"alertRules"``.
        name:          Resource name / ID.
        properties:    The resource-specific property bag.
        etag:          Optional ETag value.
        kind:          Polymorphic discriminator (alert rules, templates,
                       data connectors); emitted at the top level as ARM does.
        path:          The resource's path below the workspace provider, for a
                       child resource (``incidents/{id}/comments/{name}``);
                       defaults to ``{resource_type}/{name}``.
        type_name:     The resource type ARM names, when it is not
                       ``resource_type`` (``incidents/comments``).

    Returns:
        ARM resource dict.
    """
    fixture = _fixture_for(resource_type, kind)
    # systemData is left out of the spec defaults: the fixture's blank holds
    # `""` for createdAt and lastModifiedAt, and completing over it first
    # meant _SYSTEM_DATA below found every key present and filled nothing --
    # every resource went out with `"createdAt": ""`, which no date-time
    # parser reads (azure-mgmt-securityinsight raised DeserializationError on
    # the first page of incidents).
    defaults = {
        k: v for k, v in fixture.items()
        if k not in ("id", "name", "type", "etag", "kind", "systemData")
    }
    result: dict = {
        "id": f"{_REQUEST_BASE.get()}/{path}" if path else arm_id(resource_type, name),
        "name": name,
        "type": f"Microsoft.SecurityInsights/{type_name or resource_type}",
    }
    if kind:
        result["kind"] = kind
    if etag:
        result["etag"] = f'"{etag}"'
    result["properties"] = properties
    completed = deep_complete(defaults, result)
    if "systemData" in fixture:
        completed["systemData"] = deep_complete(
            _system_data(properties), completed.get("systemData") or {},
        )
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


def arm_deleted(existed: bool) -> Response:
    """The answer to an ARM DELETE: 200 when something went, 204 when nothing was there.

    Every Sentinel DELETE in the 2024-03-01 specification declares exactly
    200 and 204, and ARM's convention for the pair is that a delete of a
    resource that does not exist succeeds with `204 No Content` — the same
    rule the Azure REST API guidelines state ("return a 204-No Content …
    even if the URL identifies a resource that does not exist; do not return
    404-Not Found"). The mock answered 404, which a client that deletes
    idempotently, or retries a delete whose first answer it lost, reads as a
    failure.
    """
    return JSONResponse({}) if existed else Response(status_code=204)


def build_arm_error(code: str, message: str) -> dict:
    """Build an ARM error response body.

    Args:
        code:    Error code string.
        message: Human-readable error message.

    Returns:
        ARM error envelope dict.
    """
    return {"error": {"code": code, "message": message}}



def build_log_analytics_error(inner_code: str, message: str) -> dict:
    """A Log Analytics query refusal, in the Logs query API's own envelope.

    Not ARM's `{"error": {"code", "message"}}` alone: the Logs query API
    answers a query it cannot run with `BadArgumentError` and the reason in
    an `innererror` (learn.microsoft.com, Azure Monitor "Logs query
    timeouts and errors": `{"error": {"message": "The request had some
    invalid properties", "code": "BadArgumentError", "innererror": {"code":
    "SyntaxError", "message": …}}}`).

    Args:
        inner_code: ``SyntaxError`` for a query that does not parse (or that
                    this mock cannot evaluate), ``SemanticError`` for one that
                    names what the workspace does not have.
        message:    What was wrong.
    """
    return {
        "error": {
            "message": "The request had some invalid properties",
            "code": "BadArgumentError",
            "innererror": {"code": inner_code, "message": message},
        },
    }


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
