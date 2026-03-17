"""Validate mock GET responses against the bundled S1 v2.1 Swagger schema.

For every GET endpoint the mock implements that has a 200-response schema in
``data/swagger_2_1.json`` this module:

1. Calls the endpoint via the standard ``TestClient``.
2. Resolves the ``$ref`` response schema from the swagger spec.
3. Validates the response body with ``jsonschema``.

Only endpoints whose paths exist in the swagger spec *and* have a ``$ref``-based
200 response schema are covered.  Endpoints with no swagger definition (webhooks,
policies, single-agent, hash verdict) are intentionally excluded — they are
mock-only extensions that do not appear in the spec.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft4Validator, RefResolver

from repository.account_repo import account_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.threat_repo import threat_repo
from repository.user_repo import user_repo

# ---------------------------------------------------------------------------
# Swagger loading & schema helpers
# ---------------------------------------------------------------------------

_SWAGGER_PATH = Path(__file__).resolve().parents[4] / "data" / "swagger_2_1.json"
_API_PREFIX = "/web/api/v2.1"

pytestmark = pytest.mark.skipif(
    not _SWAGGER_PATH.exists(),
    reason="swagger_2_1.json not present (gitignored — local-only test)",
)


# ---------------------------------------------------------------------------
# Fields that the swagger spec declares as non-nullable strings but which the
# real S1 API can legitimately return as null (missing x-nullable in spec).
# Validated against real API behaviour — not mock gaps.
# ---------------------------------------------------------------------------
_SPEC_MISSING_NULLABLE: frozenset[str] = frozenset({
    # agents: some agents may have no container info; some timestamps can be null
    "containerInfo", "policyUpdatedAt",
    # agents: osUsername is null for non-Linux agents (swagger missing x-nullable)
    "osUsername",
    # activities: several fields are optional per activity type
    "secondaryDescription", "comments", "hash",
    # sites: these fields are not always assigned
    "externalId", "usageType", "irFields",
    # accounts: expiration only set for trial/expiring accounts
    "expiration",
    # exclusions: pathExclusionType only for path-based exclusions
    "pathExclusionType",
    # device-control: deviceId/vendorId/productId null for class-level rules
    "deviceId", "vendorId", "productId",
    # agents: operationalStateExpiration is null unless an expiry is scheduled
    "operationalStateExpiration",
    # threats: all containerInfo sub-fields are null for non-container threats
    "id", "name", "image", "labels", "isContainerQuarantine",
    # groups: creator/filterId null for system-generated or filter-less groups
    "creator", "creatorId", "filterId", "filterName",
    # firewall: protocol is null for rules matching any protocol
    "protocol",
    # alerts: sourceProcessInfo fields can be null for some alert types
    "effectiveUser", "realUser", "loginUser", "fileSignerIdentity",
    # iocs: scope/risk fields are null when globally scoped or unscored
    "parentScopeId", "scopeId", "scope", "originalRiskScore",
    # agents: scan may never have been aborted
    "scanAbortedAt",
    # activities: only set for agent-version-update events
    "agentUpdatedVersion",
    # threats: all kubernetes/container info fields null for non-k8s/non-container threats
    "cluster", "namespace", "pod", "node",
    "nodeLabels", "namespaceLabels", "podLabels", "controllerKind",
    "controllerName", "controllerLabels",
    # sites: inheritAccountExpiration can be null for some site types
    "inheritAccountExpiration",
    # groups: rank is null for non-ranked groups
    "rank",
    # device-control: uid null for class-level rules
    "uid",
    # users: apiToken null for users without an active API token
    "apiToken",
    # users: agreementUrl null when EULA already agreed
    "agreementUrl",
    # activities: threatId null for non-threat-related activities
    "threatId",
    # alerts: netEventDirection null for non-network alerts
    "netEventDirection",
    # iocs: batchId/severity null when not batch-imported or unscored
    "batchId", "severity",
    # agents: containerizedWorkloadCounts null for non-container agents
    "containerizedWorkloadCounts",
    # agents: isHyperAutomate null for non-HyperAutomate deployments
    "isHyperAutomate",
    # threats/agentRealtimeInfo: decommission info null for active agents
    "agentDecommissionedAt", "storageName", "storageType",
    # alerts: various fields null for non-matching alert types
    "dnsRequest", "dnsResponse", "commandArguments",
    # device-control: accessPermission/bluetooth/service-info null for class-level rules
    "accessPermission", "bluetoothAddress", "deviceInformationServiceInfoKey",
    "minorClass", "characteristicKey",
    # agents: remoteProfilingStateExpiration null when no profiling scheduled
    "remoteProfilingStateExpiration",
    # threats: ecsInfo sub-fields null for non-ECS threats
    "clusterName", "serviceArn", "taskArn",
    # alerts: network fields null for non-network alerts
    "dstIp", "dstPort", "srcIp", "srcPort",
    # agents: fullDiskScanLastUpdatedAt null until first scan completes
    "fullDiskScanLastUpdatedAt",
    # device-control: service info null for non-BT rules
    "deviceInformationServiceInfoValue",
    # agents: scan timestamps null when no scan has run or scan did not finish/abort
    "scanFinishedAt", "scanStartedAt", "lastSuccessfulScanDate",
    # alerts: loginAccountSid null for non-login alerts
    "loginAccountSid",
    # threats: browserType null for non-browser threats
    "browserType",
    # alerts: registryKeyPath null for non-registry alerts
    "registryKeyPath",
    # device-control: version null when not yet versioned
    "version",
    # alerts: tiIndicatorComparisonMethod/tiIndicatorValue null for non-TI alerts
    "tiIndicatorComparisonMethod", "tiIndicatorValue",
    # threats: initiatingUserId/initiatingUsername null for policy/scan-initiated detections
    "initiatingUserId", "initiatingUsername",
    # device-control: manufacturerName/deviceName null for class-level rules
    "manufacturerName", "deviceName",
    # alerts: modulePath null for non-module alerts
    "modulePath",
    # threats: cloudFilesHashVerdict null when not yet cloud-evaluated
    "cloudFilesHashVerdict",
    # threats: externalTicketId null when no external ticket
    "externalTicketId",
    # threats: rootProcessUpn null for non-AD/non-Windows threats
    "rootProcessUpn",
    # alerts: registry fields null for non-registry alerts
    "registryPath", "registryValue", "registryOldValue", "registryOldValueType",
    # alerts: module fields null for non-module alerts
    "moduleSha1",
    # alerts: login fields null for non-login alerts
    "loginAccountDomain", "loginIsSuccessful", "loginIsAdministratorEquivalent",
    "loginType", "loginsUserName",
    # alerts: indicator fields null for non-indicator alerts
    "indicatorName", "indicatorCategory", "indicatorDescription",
    # alerts: TI indicator fields null for non-TI alerts
    "tiIndicatorType", "tiIndicatorSource",
    # alerts: srcMachineIp null for non-network alerts
    "srcMachineIp",
    # alerts: sourceParentProcessInfo null when there is no parent process
    "sourceParentProcessInfo",
    # alerts/threats: kubernetesInfo null for non-container workloads
    "kubernetesInfo",
    # alerts: targetProcessInfo null when there is no target process
    "targetProcessInfo",
})

# Fields where the swagger ``type`` is wrong (real API returns a different type).
# Removing the type constraint prevents false failures on correct mock behaviour.
_SPEC_DROP_TYPE: frozenset[str] = frozenset({
    # swagger says "string" but the real API returns boolean
    "notRecommended",
})

# Fields where the swagger ``pattern`` regex is wrong/too strict.
# The real S1 API returns values that would fail the regex.
_SPEC_DROP_PATTERN: frozenset[str] = frozenset({
    # swagger uses uppercase-only email regex; real emails are lowercase
    "email",
})


def _patch_nullable(obj: Any, _parent_key: str = "") -> Any:
    """Sanitise the swagger spec so jsonschema can use it as a meta-schema.

    * ``x-nullable: true`` → ``{type: [T, "null"]}``
    * ``pattern: null`` → removed (invalid in jsonschema meta-schema)
    * ``_SPEC_MISSING_NULLABLE`` → force-allow null for fields missing x-nullable in spec
    * ``_SPEC_DROP_TYPE`` → remove ``type`` constraint for fields with wrong type in spec
    * ``_SPEC_DROP_PATTERN`` → remove ``pattern`` for fields with wrong regex in spec
    """
    if isinstance(obj, list):
        return [_patch_nullable(i) for i in obj]
    if not isinstance(obj, dict):
        return obj

    nullable = obj.get("x-nullable", False) or _parent_key in _SPEC_MISSING_NULLABLE
    patched: dict[str, Any] = {
        k: _patch_nullable(v, _parent_key=k)
        for k, v in obj.items()
        if k != "x-nullable"
        and not (k == "pattern" and v is None)
        and not (k == "type" and _parent_key in _SPEC_DROP_TYPE)
        and not (k == "pattern" and _parent_key in _SPEC_DROP_PATTERN)
    }

    if nullable:
        if "type" in patched:
            t = patched["type"]
            patched["type"] = ([t, "null"] if isinstance(t, str) else list(t) + ["null"])
        # Enum fields also need null in the allowed set
        if "enum" in patched and None not in patched["enum"]:
            patched["enum"] = patched["enum"] + [None]

    return patched


@pytest.fixture(scope="module")
def swagger() -> dict[str, Any]:
    """Load and return the nullable-patched swagger spec (loaded once per module)."""
    with _SWAGGER_PATH.open() as fh:
        raw = json.load(fh)
    return _patch_nullable(raw)  # type: ignore[return-value]


@pytest.fixture(scope="module")
def resolver(swagger: dict[str, Any]) -> RefResolver:
    """Return a jsonschema RefResolver anchored to the swagger spec."""
    return RefResolver.from_schema(swagger)


def _get_200_schema(swagger: dict[str, Any], rel_path: str, method: str = "get") -> dict[str, Any]:
    """Resolve and return the 200-response schema for a swagger path + method.

    Args:
        swagger: The patched swagger spec dict.
        rel_path: Path relative to ``/web/api/v2.1``, e.g. ``/agents``.
        method: HTTP method (lower-case).

    Returns:
        The resolved schema dict.

    Raises:
        KeyError: If the path or 200 response schema is not found.
    """
    full_path = f"{_API_PREFIX}{rel_path}"
    op = swagger["paths"][full_path][method]
    ref: str = op["responses"]["200"]["schema"]["$ref"]
    parts = ref.lstrip("#/").split("/")
    node: Any = swagger
    for part in parts:
        node = node[part]
    return node  # type: ignore[return-value]


def _assert_valid(
    body: Any,
    schema: dict[str, Any],
    resolver: RefResolver,
) -> None:
    """Validate ``body`` against ``schema`` using Draft4Validator.

    Using the validator instance directly (rather than the module-level
    ``validate()`` function) skips the meta-schema check.  This is intentional:
    the S1 swagger 2.0 spec contains ``"format": null`` and ``"default": null``
    entries that are valid in JSON Schema Draft 4 context but rejected by the
    Draft 2020-12 meta-schema that ``validate()`` auto-selects.
    """
    Draft4Validator(schema, resolver=resolver).validate(body)


# ---------------------------------------------------------------------------
# Parameterised GET list endpoints (no path parameters required)
# ---------------------------------------------------------------------------

_LIST_ENDPOINTS: list[tuple[str, str]] = [
    # label                      swagger rel-path
    ("agents",                   "/agents"),
    ("agents_count",             "/agents/count"),
    ("agents_applications",      "/agents/applications"),
    ("agents_processes",         "/agents/processes"),
    ("agents_tags",              "/agents/tags"),
    ("activities",               "/activities"),
    ("activity_types",           "/activities/types"),
    ("threats",                  "/threats"),
    ("sites",                    "/sites"),
    ("groups",                   "/groups"),
    ("exclusions",               "/exclusions"),
    ("restrictions",             "/restrictions"),
    ("alerts",                   "/cloud-detection/alerts"),
    ("firewall_rules",           "/firewall-control"),
    ("device_control_rules",     "/device-control"),
    ("iocs",                     "/threat-intelligence/iocs"),
    ("users",                    "/users"),
    ("accounts",                 "/accounts"),
    ("system_status",            "/system/status"),
    ("system_info",              "/system/info"),
    ("system_configuration",     "/system/configuration"),
]


class TestGetListEndpoints:
    """Validate all GET list-endpoint responses against their swagger schema."""

    @pytest.mark.parametrize("label,rel_path", _LIST_ENDPOINTS, ids=[e[0] for e in _LIST_ENDPOINTS])
    def test_response_matches_swagger_schema(
        self,
        label: str,
        rel_path: str,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET {rel_path} must satisfy the swagger 200-response schema."""
        schema = _get_200_schema(swagger, rel_path)
        resp = client.get(f"{_API_PREFIX}{rel_path}", headers=auth_headers)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:200]}"
        _assert_valid(resp.json(), schema, resolver)


# ---------------------------------------------------------------------------
# Single-item GET endpoints (path parameters resolved from seeded repos)
# ---------------------------------------------------------------------------


class TestGetSingleEndpoints:
    """Validate GET single-item responses against their swagger schema."""

    def test_site(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /sites/{site_id} must satisfy schema."""
        site_id = site_repo.list_all()[0].id
        schema = _get_200_schema(swagger, "/sites/{site_id}")
        resp = client.get(f"{_API_PREFIX}/sites/{site_id}", headers=auth_headers)
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)

    def test_group(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /groups/{group_id} must satisfy schema."""
        group_id = group_repo.list_all()[0].id
        schema = _get_200_schema(swagger, "/groups/{group_id}")
        resp = client.get(f"{_API_PREFIX}/groups/{group_id}", headers=auth_headers)
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)

    def test_user(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /users/{user_id} must satisfy schema."""
        user_id = user_repo.list_all()[0].id
        schema = _get_200_schema(swagger, "/users/{user_id}")
        resp = client.get(f"{_API_PREFIX}/users/{user_id}", headers=auth_headers)
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)

    def test_account(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /accounts/{account_id} must satisfy schema."""
        account_id = account_repo.list_all()[0].id
        schema = _get_200_schema(swagger, "/accounts/{account_id}")
        resp = client.get(f"{_API_PREFIX}/accounts/{account_id}", headers=auth_headers)
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)

    def test_threat_notes(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /threats/{threat_id}/notes must satisfy schema."""
        threat_id = threat_repo.list_all()[0].id
        schema = _get_200_schema(swagger, "/threats/{threat_id}/notes")
        resp = client.get(f"{_API_PREFIX}/threats/{threat_id}/notes", headers=auth_headers)
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)

    def test_threat_timeline(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /threats/{threat_id}/timeline must satisfy schema."""
        threat_id = threat_repo.list_all()[0].id
        schema = _get_200_schema(swagger, "/threats/{threat_id}/timeline")
        resp = client.get(f"{_API_PREFIX}/threats/{threat_id}/timeline", headers=auth_headers)
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)


# ---------------------------------------------------------------------------
# Deep Visibility endpoints (require an active query)
# ---------------------------------------------------------------------------


class TestDeepVisibilitySpec:
    """Validate DV endpoints whose responses have swagger schemas."""

    @pytest.fixture()
    def query_id(self, client: TestClient, auth_headers: dict[str, str]) -> str:
        """Create a DV query and return its ID."""
        resp = client.post(
            f"{_API_PREFIX}/dv/init-query",
            headers=auth_headers,
            json={
                "query": "EventType = 'Process Creation'",
                "fromDate": "2024-01-01T00:00:00Z",
                "toDate": "2024-12-31T23:59:59Z",
            },
        )
        assert resp.status_code == 200
        return resp.json()["data"]["queryId"]  # type: ignore[no-any-return]

    def test_query_status(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        query_id: str,
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /dv/query-status must satisfy schema."""
        schema = _get_200_schema(swagger, "/dv/query-status")
        resp = client.get(
            f"{_API_PREFIX}/dv/query-status", headers=auth_headers, params={"queryId": query_id}
        )
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)

    def test_events(
        self,
        client: TestClient,
        auth_headers: dict[str, str],
        query_id: str,
        swagger: dict[str, Any],
        resolver: RefResolver,
    ) -> None:
        """GET /dv/events must satisfy schema."""
        schema = _get_200_schema(swagger, "/dv/events")
        resp = client.get(
            f"{_API_PREFIX}/dv/events", headers=auth_headers, params={"queryId": query_id}
        )
        assert resp.status_code == 200
        _assert_valid(resp.json(), schema, resolver)
