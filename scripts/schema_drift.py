# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR0912, PLR0915, PLR2004
# A release tool, not library code; sys.path is set before the project imports.
"""Compare mockdr's responses against a vendor's published API specification.

For the six platforms that cannot be run locally the specification is the
only reference. This takes a Swagger 2.0 or OpenAPI 3 file, finds the spec
path for each mockdr route on a mount, resolves the 200 response schema to
its property names (following $ref, allOf, and the `properties`/`value`
envelopes the vendors use), calls mockdr through the TestClient, and
reports properties the spec declares that mockdr does not return, and
properties mockdr returns that the spec does not declare.

    backend/.venv/bin/python scripts/schema_drift.py sentinel
    backend/.venv/bin/python scripts/schema_drift.py graph

A missing property is what a client reads and finds absent; an extra one
is a claim the vendor never made. Neither is proof of a wrong *value* — the
spec says nothing about values — but both are the kind of drift a mock
accumulates silently.
"""

from __future__ import annotations

import functools
import json
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")

from fastapi.testclient import TestClient  # noqa: E402

SPECS = ROOT / "data" / "vendor-specs"


def load_specs(platform: str) -> list[dict]:
    files = {
        "graph": [],
        "sentinel": sorted(SPECS.glob("sentinel_2024-03-01_*.json")),
        "sentinelone": [SPECS.parent / "swagger_2_1.json"],
    }[platform]
    return [json.load(open(f)) for f in files if f.exists()]


_FILES: dict[str, dict] = {}


def _load_ref_file(ref_path: str) -> dict:
    """A spec file referenced by relative path.

    Azure's common types live by version under common-types/; Sentinel's own
    shared definitions (./common/2.0/types.json, ./common/AlertTypes.json)
    beside the version's spec files. Both are vendored under data/vendor-specs.
    """
    common = re.search(r"common-types/resource-management/(v\d+)/types\.json", ref_path)
    versioned = re.search(r"common/(\d+\.\d+)/types\.json", ref_path)
    named = re.search(r"common/(\w+)\.json", ref_path)
    if ref_path.startswith("preview:"):
        key, candidate = (ref_path, SPECS / f"sentinel_{ref_path[8:]}_openapi.json")
    elif common:
        key, candidate = (
            f"common-types/{common.group(1)}",
            SPECS / "common-types" / f"{common.group(1)}.json",
        )
    elif versioned:
        key, candidate = (
            f"sentinel-common/{versioned.group(1)}",
            SPECS / "sentinel-common" / f"{versioned.group(1)}_types.json",
        )
    elif named:
        key, candidate = (
            f"sentinel-common/{named.group(1)}",
            SPECS / "sentinel-common" / f"{named.group(1)}.json",
        )
    else:
        key, candidate = Path(ref_path).name, SPECS / Path(ref_path).name
    if key not in _FILES:
        _FILES[key] = json.load(open(candidate)) if candidate.exists() else {}
    return _FILES[key]


def _qualify(node, file_part: str):
    """Rewrite bare ``#/`` refs inside a subtree loaded from ``file_part``.

    A definition in common-types refers to its siblings as ``#/definitions/x``;
    resolved against the Sentinel file that pulled it in, that lookup finds
    nothing and ``systemData`` silently became ``{}``.
    """
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "$ref" and isinstance(v, str) and v.startswith("#"):
                out[k] = file_part + v
            else:
                out[k] = _qualify(v, file_part)
        return out
    if isinstance(node, list):
        return [_qualify(v, file_part) for v in node]
    return node


def deref(doc: dict, node):
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        ref = node["$ref"]
        file_part, _, pointer = ref.partition("#")
        target = _load_ref_file(file_part) if file_part else doc
        for part in pointer.lstrip("/").split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        node = _qualify(target, file_part) if file_part else target
        seen += 1
    return node


def props(doc: dict, schema, depth: int = 0) -> dict:
    schema = deref(doc, schema)
    if depth > 8 or not isinstance(schema, dict):
        return {}
    out = dict(schema.get("properties", {}))
    for part in schema.get("allOf", []):
        out.update(props(doc, part, depth + 1))
    return out


def base_name(doc: dict, schema) -> str:
    """The definition a response's items are typed with.

    A list response is a ``$ref`` to ``XList`` whose ``value.items`` name the
    base; a single response is the base itself.
    """
    if not isinstance(schema, dict):
        return ""
    own = schema.get("$ref", "").rsplit("/", 1)[-1]
    resolved = deref(doc, schema)
    items = (
        resolved.get("properties", {}).get("value", {}).get("items", {})
        if isinstance(resolved, dict)
        else {}
    )
    return items.get("$ref", "").rsplit("/", 1)[-1] or own


@functools.cache
def _preview_definitions() -> tuple[dict, ...]:
    """Preview specs, for definitions only: kinds ARM returns that stable lacks.

    A workspace lists its codeless (``GenericUI``) connectors under any
    api-version, but only the preview spec declares their shape. The preview
    *paths* are not compared — the stable spec is the contract.
    """
    docs = []
    for path in sorted(SPECS.glob("sentinel_*-preview_openapi.json")):
        doc = json.load(open(path))
        tag = "preview:" + path.name[len("sentinel_") : -len("_openapi.json")]
        docs.append({"definitions": _qualify(doc.get("definitions", {}), tag)})
    return tuple(docs)


def derived_for_kind(doc: dict, kind: str, base: str = "") -> dict | None:
    """The definition whose x-ms-discriminator-value is `kind`.

    ``Scheduled`` names both ScheduledAlertRule and ScheduledAlertRuleTemplate,
    so the match is restricted to definitions extending ``base`` when known.
    """
    fallback = None
    for d in [doc, *_FILES.values(), *_preview_definitions()]:
        for definition in d.get("definitions", {}).values():
            if (
                not isinstance(definition, dict)
                or definition.get("x-ms-discriminator-value") != kind
            ):
                continue
            parents = [a.get("$ref", "").rsplit("/", 1)[-1] for a in definition.get("allOf", [])]
            if base and base in parents:
                return definition
            fallback = fallback or definition
    return None if base and fallback is None else fallback


def flatten(doc: dict, schema, prefix: str = "", depth: int = 0) -> set[str]:
    """Every property path the schema declares, dotted, arrays as [*]."""
    out: set[str] = set()
    for name, sub in props(doc, schema, depth).items():
        path = f"{prefix}{name}"
        out.add(path)
        sub = deref(doc, sub)
        if not isinstance(sub, dict) or depth > 6:
            continue
        if sub.get("type") == "array":
            out |= flatten(doc, sub.get("items", {}), f"{path}[*].", depth + 1)
        elif "properties" in sub or "allOf" in sub or "$ref" in sub:
            out |= flatten(doc, sub, f"{path}.", depth + 1)
    return out


def observed(value, prefix: str = "", depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 8:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}{k}")
            out |= observed(v, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        for item in value[:3]:
            out |= observed(item, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)
    return out


def observed_opaque(value, prefix: str = "", depth: int = 0) -> set[str]:
    """Paths below which nothing can be observed: empty arrays."""
    out: set[str] = set()
    if depth > 8:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            if v is None:
                out.add(f"{prefix}{k}")  # a null object has no observable members
            out |= observed_opaque(v, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        if not value:
            out.add(f"{prefix[:-1]}[*]")
        for item in value[:3]:
            out |= observed_opaque(item, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)
    return out


def declared_opaque(doc: dict, schema, prefix: str = "", depth: int = 0) -> set[str]:
    """Paths the spec leaves free-form: objects without declared properties."""
    out: set[str] = set()
    for name, sub in props(doc, schema, depth).items():
        path = f"{prefix}{name}"
        sub = deref(doc, sub)
        if not isinstance(sub, dict) or depth > 6:
            continue
        if sub.get("type") == "array":
            items = deref(doc, sub.get("items", {}))
            if not isinstance(items, dict) or not (
                items.get("properties")
                or items.get("allOf")
                or items.get("type") not in (None, "object")
            ):
                out.add(f"{path}[*]")  # items declared as bare objects: members unknown
            else:
                out |= declared_opaque(doc, items, f"{path}[*].", depth + 1)
        elif "properties" in sub or "allOf" in sub:
            out |= declared_opaque(doc, sub, f"{path}.", depth + 1)
        elif (
            sub.get("type") == "object"
            or "additionalProperties" in sub
            or not sub
            or (sub.get("type") is None and "$ref" not in sub)
        ):
            out.add(path)  # declared without a member schema: members unknown
    return out


def _under(path: str, prefixes: set[str]) -> bool:
    return any(path == o or path.startswith(o + ".") or path.startswith(o + "[") for o in prefixes)


@functools.cache
def _graph_types() -> dict:
    path = SPECS / "graph_v1.0_types.json"
    return json.load(open(path)) if path.exists() else {}


def graph_typed_objects(value: object, path: str = "") -> list[tuple[str, str, set[str]]]:
    """Every nested object that names its own type, and the keys it carries.

    The comparison used to stop at an item's top-level keys, so a nested
    object could carry anything at all — which is how an alert's `evidence`
    came to hold two properties Graph has never had while this reported no
    drift. OData marks a typed object with ``@odata.type``, and that is
    exactly the handle needed to judge it.
    """
    found: list[tuple[str, str, set[str]]] = []
    if isinstance(value, dict):
        declared = str(value.get("@odata.type") or "").lstrip("#")
        if declared and path:
            found.append((path, declared, {k for k in value if not k.startswith("@odata")}))
        for key, member in value.items():
            found += graph_typed_objects(member, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        for member in value[:3]:
            found += graph_typed_objects(member, f"{path}[]")
    return found


def graph_type_props(type_name: str) -> set[str]:
    """The properties graph_v1.0_types.json declares for ``microsoft.graph.X``."""
    entry = _graph_types().get(type_name)
    if isinstance(entry, dict):
        return set(entry.get("properties", entry))
    return set(entry or [])


def shape(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path.lower())


def _cs_prepare(client: TestClient, headers: dict) -> dict:
    """Ids for CrowdStrike's entities routes, from its queries routes."""
    ctx: dict = {}
    for name, url in {
        "device_ids": "/cs/devices/queries/devices/v1",
        "alert_ids": "/cs/alerts/queries/alerts/v2",
        "ioc_ids": "/cs/iocs/combined/indicator/v1",
        "quarantine_ids": "/cs/quarantine/queries/quarantined-files/v1",
        "user_uuids": "/cs/user-management/queries/users/v1",
        "group_ids": "/cs/devices/combined/host-groups/v1",
        "case_ids": "/cs/cases/queries/cases/v1",
    }.items():
        r = client.get(url, headers=headers, params={"limit": 3})
        resources = r.json().get("resources", []) if r.status_code == 200 else []
        ctx[name] = [x["id"] if isinstance(x, dict) else x for x in resources][:3]
    return ctx


def _xdr_prepare(client: TestClient, headers: dict) -> dict:
    """Ids for Cortex XDR's entity routes, from its list routes."""

    def post(path: str) -> dict:
        r = client.post("/xdr" + path, headers=headers, json={"request_data": {}})
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        reply = body.get("reply") if isinstance(body, dict) else None
        return reply if isinstance(reply, dict) else {}

    incidents = post("/public_api/v1/incidents/get_incidents/").get("incidents", [])
    endpoints = post("/public_api/v1/endpoints/get_endpoint/").get("endpoints", [])
    scripts = post("/public_api/v1/scripts/get_scripts/").get("scripts", [])
    return {
        "incident_id": incidents[0]["incident_id"] if incidents else "1",
        "endpoint_id": endpoints[0]["endpoint_id"] if endpoints else "x",
        "script_uid": scripts[0]["script_uid"] if scripts else "x",
    }


PLATFORMS = {
    "crowdstrike": {
        "kind": "paths",
        "extras_only": True,
        "mount": "/cs",
        "reduced": SPECS / "crowdstrike_gofalcon_reduced.json",
        "auth": lambda c: _oauth(
            c, "/cs/oauth2/token", "cs-mock-admin-client", "cs-mock-admin-secret"
        ),
        "prepare": _cs_prepare,
        "default_body": {},
        "requests": {
            "POST /devices/entities/devices/v2": {"json": {"ids": "{device_ids}"}},
            "GET /devices/entities/host-groups/v1": {"params": {"ids": "{group_ids}"}},
            "GET /devices/combined/host-group-members/v1": {"params": {"id": "{group_ids}"}},
            "POST /alerts/entities/alerts/v2": {"json": {"composite_ids": "{alert_ids}"}},
            "GET /iocs/entities/indicators/v1": {"params": {"ids": "{ioc_ids}"}},
            "POST /user-management/entities/users/GET/v1": {"json": {"ids": "{user_uuids}"}},
            "POST /quarantine/entities/quarantined-files/GET/v1": {
                "json": {"ids": "{quarantine_ids}"}
            },
        },
    },
    "xdr": {
        "kind": "paths",
        "missing_only": True,
        "mount": "/xdr",
        "reduced": SPECS / "xdr_samples_reduced.json",
        # Response shapes transcribed from the official reference (see
        # scripts/cortex_openapi_spec.py); presence only, like a recording.
        "reduced_extra": [
            SPECS / "xdr_openapi_reduced.json",
            SPECS / "xdr_core_samples_reduced.json",
            SPECS / "xdr_connector_reduced.json",
            SPECS / "xdr_alerts_multi_events_reduced.json",
        ],
        "auth": lambda c: {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"},
        "prepare": _xdr_prepare,
        "default_body": {"request_data": {}},
        "requests": {
            "POST /public_api/v1/incidents/get_incident_extra_data/": {
                "json": {"request_data": {"incident_id": "{incident_id}"}}
            },
            "POST /public_api/v1/incidents/update_incident/": {
                "json": {
                    "request_data": {
                        "incident_id": "{incident_id}",
                        "update_data": {"status": "under_investigation"},
                    }
                }
            },
            "POST /public_api/v1/endpoints/isolate": {
                "json": {"request_data": {"endpoint_id": "{endpoint_id}"}}
            },
            "POST /public_api/v1/endpoints/unisolate": {
                "json": {"request_data": {"endpoint_id": "{endpoint_id}"}}
            },
            "POST /public_api/v1/endpoints/scan/": {
                "json": {
                    "request_data": {
                        "filters": [
                            {
                                "field": "endpoint_id_list",
                                "operator": "in",
                                "value": ["{endpoint_id}"],
                            }
                        ]
                    }
                }
            },
            "POST /public_api/v1/scripts/get_script_metadata/": {
                "json": {"request_data": {"script_uid": "{script_uid}"}}
            },
            "POST /public_api/v1/scripts/run_script/": {
                "json": {
                    "request_data": {
                        "script_uid": "{script_uid}",
                        "timeout": 600,
                        "filters": [
                            {
                                "field": "endpoint_id_list",
                                "operator": "in",
                                "value": ["{endpoint_id}"],
                            }
                        ],
                        "parameters_values": {},
                    }
                }
            },
            "POST /public_api/v1/alerts/insert_cef_alerts/": {
                "json": {"request_data": {"alerts": ["CEF:0|mockdr|drift|1|1|drift|1|"]}}
            },
        },
    },
    "mde": {
        "kind": "paths",
        "missing_only": True,
        "skip": {"POST /api/advancedqueries/run": "columns are the query's, not the API's"},
        "mount": "/mde",
        "reduced": SPECS / "mde_docs_reduced.json",
        "reduced_extra": [SPECS / "mde_samples_reduced.json"],
        # The OData envelope every MDE list carries.
        "envelope": ["@odata.context", "@odata.nextLink", "@odata.count", "value"],
        "auth": lambda c: _oauth(
            c,
            "/mde/oauth2/v2.0/token",
            "mde-mock-admin-client",
            "mde-mock-admin-secret",
            "https://api.securitycenter.microsoft.com/.default",
        ),
        "default_body": {"Comment": "schema drift"},
        "entities": {
            "/api/alerts": "alerts",
            "/api/machines": "machine",
            "/api/machineactions": "machineaction",
            "/api/investigations": "investigation",
            "/api/indicators": "ti-indicator",
            "/api/vulnerabilities": "vulnerability",
            "/api/software": "software",
            "/api/files": "files",
            "/api/exposureScore": "score",
            # machine actions answer with a machineAction, whatever they act on
            "POST /api/machines/{id}/isolate": "machineaction",
            "POST /api/machines/{id}/unisolate": "machineaction",
            "POST /api/machines/{id}/runAntiVirusScan": "machineaction",
            "POST /api/machines/{id}/collectInvestigationPackage": "machineaction",
            "POST /api/machines/{id}/restrictCodeExecution": "machineaction",
            "POST /api/machines/{id}/unrestrictCodeExecution": "machineaction",
            "POST /api/machines/{id}/offboard": "machineaction",
            "POST /api/machines/{id}/StopAndQuarantineFile": "machineaction",
            "PATCH /api/alerts/{id}": "alerts",
            "POST /api/alerts/{id}": "alerts",
        },
        "requests": {
            "POST /api/machines/{id}/isolate": {
                "json": {"Comment": "drift", "IsolationType": "Full"}
            },
            "POST /api/machines/{id}/runAntiVirusScan": {
                "json": {"Comment": "drift", "ScanType": "Quick"}
            },
            "POST /api/advancedqueries/run": {"json": {"Query": "DeviceInfo | take 1"}},
        },
    },
    "sentinelone": {
        "mount": "/web/api/v2.1",
        "auth": lambda c: {"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
        "optional_top": ("errors",),
        "spec_prefix": "/web/api/v2.1",
        "params": {},
        "fill": {},
    },
    "graph": {
        "mount": "/graph",
        "reduced": SPECS / "graph_v1.0_reduced.json",
        "auth": lambda c: {
            "Authorization": "Bearer "
            + c.post(
                "/graph/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "graph-mock-admin-client",
                    "client_secret": "graph-mock-admin-secret",
                    "scope": "https://graph.microsoft.com/.default",
                },
            ).json()["access_token"]
        },
        "params": {},
        "fill": {},
    },
    "sentinel": {
        "mount": "/sentinel",
        "routers": "backend/api/routers/sentinel/*.py",
        "auth": lambda c: {
            "Authorization": "Bearer "
            + c.post(
                "/sentinel/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": "sentinel-mock-client-id",
                    "client_secret": "sentinel-mock-client-secret",
                    "scope": "https://management.azure.com/.default",
                },
            ).json()["access_token"]
        },
        "params": {"api-version": "2024-03-01"},
        "fill": {
            "subscriptionId": "00000000-0000-0000-0000-000000000000",
            "resourceGroupName": "rg",
            "workspaceName": "ws",
            "incidentId": "{first}",
            "ruleId": "{first}",
            "bookmarkId": "{first}",
            "watchlistAlias": "{first}",
            "name": "{first}",
        },
    },
}


def _ids(client: TestClient, collection_url: str, headers: dict, params: dict) -> list[str]:
    """Entity ids from a collection, for filling a `{…Id}` segment."""
    r = client.get(collection_url, headers=headers, params=params)
    if r.status_code != 200 or not r.headers.get("content-type", "").startswith("application/json"):
        return []
    body = r.json()
    items = body
    if isinstance(body, dict):
        items = body.get("value") or body.get("data") or body.get("resources")
        if items is None and isinstance(body.get("reply"), dict):
            items = next((v for v in body["reply"].values() if isinstance(v, list)), None)
    out = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        ident = item.get("id")
        if not isinstance(ident, str) or "/" in ident:
            ident = (
                item.get("name")
                or item.get("alias")
                or item.get("incident_id")
                or item.get("endpoint_id")
                or item.get("script_uid")
                or ident
            )
        if ident:
            out.append(str(ident))
    return out


def _first_id(client: TestClient, collection_url: str, headers: dict, params: dict) -> str | None:
    ids = _ids(client, collection_url, headers, params)
    return ids[0] if ids else None


def _fill(
    client: TestClient, route: str, headers: dict, params: dict, fill: dict, mount: str = ""
) -> str:
    """Replace path parameters: fixed values from `fill`, ids from the collection."""
    out = route
    for param in re.findall(r"\{([^}]+)\}", route):
        if param in fill and fill[param] != "{first}":
            out = out.replace("{" + param + "}", fill[param])
    # A nested collection (incidents/{id}/comments) may be empty under the
    # first parent; walk the parents until one has children.
    filled: list[tuple[str, str, list[str]]] = []  # (param, chosen, candidates)
    for param in re.findall(r"\{([^}]+)\}", out):
        collection = out.split("{" + param + "}")[0].rstrip("/")
        ids = _ids(client, mount + collection, headers, params)
        if not ids and filled:
            p_param, chosen, candidates = filled[-1]
            for candidate in candidates[1:50]:
                retry = collection.replace("/" + chosen + "/", "/" + candidate + "/")
                retry = retry[: -len(chosen)] + candidate if retry.endswith("/" + chosen) else retry
                ids = _ids(client, mount + retry, headers, params)
                if ids:
                    out = out.replace("/" + chosen, "/" + candidate, 1)
                    filled[-1] = (p_param, candidate, candidates)
                    break
        chosen = ids[0] if ids else "x"
        out = out.replace("{" + param + "}", chosen)
        filled.append((param, chosen, ids))
    return out


def _oauth(client: TestClient, url: str, client_id: str, secret: str, scope: str = "") -> dict:
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if scope:
        data["scope"] = scope
    return {"Authorization": "Bearer " + client.post(url, data=data).json()["access_token"]}


def _substitute(value, ctx: dict):
    """Fill ``{name}`` placeholders from ctx; a list placeholder stays a list."""
    if isinstance(value, str):
        m = re.fullmatch(r"\{(\w+)\}", value)
        if m:
            return ctx.get(m.group(1), value)
        return value
    if isinstance(value, dict):
        return {k: _substitute(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(v, ctx) for v in value]
    return value


def _compare_paths(platform: str, cfg: dict, client: TestClient, headers: dict, routes: set) -> int:
    """Compare the mock against a route → declared key-path map.

    The map comes from a generated SDK (gofalcon), a docs tree (MDE) or
    recorded responses (XSOAR samples) — see the scripts that write them.
    Each entry lists the dotted paths a real response carries; the mock's
    response is flattened the same way. Empty arrays are unobservable, not
    missing; ``{id}`` is normalised on both sides.
    """
    mount = cfg["mount"]
    declared_by_route: dict[str, set] = {}
    for source in [cfg["reduced"], *cfg.get("reduced_extra", [])]:
        doc = json.load(open(source))
        for key, entry in (doc.get("routes") or doc).items():
            if isinstance(entry, dict) and "paths" in entry and " " in key:
                declared_by_route.setdefault(key, set()).update(entry["paths"])
    entities = {}
    for source in [cfg["reduced"], *cfg.get("reduced_extra", [])]:
        entities.update(json.load(open(source)).get("entities") or {})
    # Docs spell paths with their own casing (/api/Software, CreateAlertByReference);
    # the API is case-insensitive, so keys are matched lower-cased.
    norm = lambda p: re.sub(r"\{[^}]+\}", "{id}", p).lower().rstrip("/") or "/"  # noqa: E731
    mock = {(m, norm(r)): r for m, r in routes}
    declared_by_route = {
        f"{k.split(' ', 1)[0]} {norm(k.split(' ', 1)[1])}": v for k, v in declared_by_route.items()
    }
    ctx = cfg["prepare"](client, headers) if "prepare" in cfg else {}
    findings = checked = 0
    unjudged = sorted(
        f"{m} {mock[(m, r)]}" for (m, r) in mock if f"{m} {r}" not in declared_by_route
    )
    for key in sorted(declared_by_route):
        method, route = key.split(" ", 1)
        if (method, route) not in mock:
            continue
        if key in cfg.get("skip", {}):
            print(f"  -  {method} {route}: {cfg['skip'][key]} (skipped)")
            continue
        real_route = mock[(method, route)]
        route = real_route
        url = _fill(client, real_route, headers, cfg.get("params", {}), cfg.get("fill", {}), mount)
        req = _substitute(cfg.get("requests", {}).get(key, {}), ctx)
        params = {**cfg.get("params", {}), **req.get("params", {})}
        body = req.get("json", cfg.get("default_body") if method != "GET" else None)
        try:
            r = client.request(method, mount + url, headers=headers, params=params, json=body)
        except Exception as exc:  # noqa: BLE001 — the crash is the finding
            findings += 1
            print(f"  {method} {route}\n      crash    {type(exc).__name__}: {exc}")
            continue
        if r.status_code >= 300 or not r.headers.get("content-type", "").startswith(
            "application/json"
        ):
            print(f"  -  {method} {route}: HTTP {r.status_code} (skipped)")
            continue
        payload = r.json()
        checked += 1
        declared = set(declared_by_route[key]) | set(cfg.get("envelope", []))
        # An entity table applies to the route's items: value[*].<prop> on a
        # list, <prop> on a single resource.
        for prefix, entity in cfg.get("entities", {}).items():
            if (key == prefix or route in (prefix, prefix + "/{id}")) and entity in entities:
                is_list = isinstance(payload, dict) and isinstance(payload.get("value"), list)
                declared |= {("value[*]." if is_list else "") + p for p in entities[entity]}
        seen = observed(payload)
        unobservable = observed_opaque(payload)
        # A declared container with no declared children (a docs table names
        # ``ipAddresses`` but not its members) is opaque: its members are
        # neither missing nor extra.
        free = set(cfg.get("free_form", [])) | {
            p
            for p in declared
            if not any(q.startswith((p + ".", p + "[")) for q in declared)
            and any(q.startswith((p + ".", p + "[")) for q in seen)
        }
        # Envelope members are declared but conditional (@odata.count needs
        # $count=true); a docs table may capitalise a key the API does not.
        optional = set(cfg.get("envelope", []))
        seen_ci = {p.lower() for p in seen}
        missing = sorted(
            p
            for p in declared
            if p not in seen
            and p.lower() not in seen_ci
            and not p.endswith("[*]")
            and p not in optional
            and not _under(p, unobservable)
        )
        declared_ci = {p.lower() for p in declared}
        extra = sorted(
            p
            for p in seen
            if p not in declared
            and p.lower() not in declared_ci
            and "[*]" not in p.split(".")[-1]
            and not _under(p, free)
        )
        # A generated SDK (gofalcon) declares every field a model *can* carry,
        # omitted when empty — absence is not drift there; coverage is printed.
        # A recorded response or a docs example proves what a real response
        # carries, never what it does not: for those references only absence
        # is drift, and surplus is listed as undocumented without counting.
        undocumented = extra if cfg.get("missing_only") else []
        if cfg.get("missing_only"):
            extra = []
        if cfg.get("extras_only"):
            print(
                f"  ·  {method} {route}: "
                f"{len(declared & seen)}/{len(declared)} declared paths present"
            )
            missing = []
        if missing or extra or undocumented:
            findings += len(missing) + len(extra)
            print(f"  {method} {route}")
            for p in missing[:12]:
                print(f"      missing  {p}")
            for p in extra[:12]:
                print(f"      extra    {p}")
            for p in undocumented[:6]:
                print(f"      undocumented {p}")
            if len(missing) > 12 or len(extra) > 12:
                more_missing = max(0, len(missing) - 12)
                print(f"      … {more_missing} more missing, {max(0, len(extra) - 12)} more extra")
    if unjudged:
        print(f"\n  {len(unjudged)} mock route(s) the reference does not describe:")
        for u in unjudged:
            print(f"      {u}")
    print(f"\n{platform}: {checked} routes compared, {findings} drift findings")
    return 1 if findings else 0


def main(platform: str) -> int:
    # Imported here so the schema helpers above stay usable without the app.
    from main import app  # noqa: PLC0415

    cfg = PLATFORMS[platform]
    client = TestClient(app).__enter__()
    headers = cfg["auth"](client)
    mount = cfg["mount"]
    routes: set[tuple[str, str]] = set()
    for path, methods in app.openapi()["paths"].items():
        if path.startswith(mount + "/"):
            for method in methods:
                routes.add((method.upper(), path[len(mount) :]))

    findings = 0
    checked = 0
    if cfg.get("kind") == "paths":
        return _compare_paths(platform, cfg, client, headers, routes)
    if "reduced" in cfg:
        reduced = json.load(open(cfg["reduced"]))
        # Beta routes are judged by the beta metadata where it was reduced
        # (data/vendor-specs/graph_beta_reduced.json); the rest are skipped.
        beta = SPECS / "graph_beta_reduced.json"
        if beta.exists():
            reduced.update(json.load(open(beta)))
        for key, entry in sorted(reduced.items()):
            if not entry.get("spec"):
                continue
            method, route = key.split(" ", 1)
            if method != "GET":
                continue
            if route.startswith("/beta/") and entry.get("spec") != "beta":
                print(f"  -  {method} {route}: beta route, v1.0 metadata cannot judge it (skipped)")
                continue
            url = _fill(client, route, headers, cfg["params"], cfg["fill"], mount)
            r = client.get(mount + url, headers=headers, params=cfg["params"])
            if r.status_code != 200:
                print(f"  -  {method} {route}: HTTP {r.status_code} (skipped)")
                continue
            body = r.json()
            checked += 1
            if entry.get("item") and isinstance(body, dict) and isinstance(body.get("value"), list):
                declared = set(entry["item"])
                seen = set()
                for item in body["value"][:3]:
                    seen |= set(item) if isinstance(item, dict) else set()
                    # OData polymorphism: an item's @odata.type names the
                    # derived type whose properties it carries.
                    derived = item.get("@odata.type", "") if isinstance(item, dict) else ""
                    declared |= graph_type_props(derived.lstrip("#"))
                envelope_seen = {k for k in body if k != "value"}
                envelope_declared = {k for k in entry["top"] if k != "value"}
            else:
                declared = set(entry["top"])
                seen = set(body) if isinstance(body, dict) else set()
                envelope_seen = envelope_declared = set()
            # Nested typed objects, judged against the type they name.
            nested_extra: list[tuple[str, str, str]] = []
            for item in (body.get("value", [])[:3]
                         if isinstance(body.get("value"), list) else [body]):
                for where, type_name, keys in graph_typed_objects(item):
                    known = graph_type_props(type_name)
                    if not known:
                        continue
                    nested_extra += [
                        (where, type_name, key) for key in sorted(keys - known)
                    ]

            missing = sorted(declared - seen)
            extra = sorted(seen - declared)
            env_missing = sorted(envelope_declared - envelope_seen)
            env_extra = sorted(
                k for k in envelope_seen - envelope_declared if not k.startswith("@odata")
            )
            env_missing = [p for p in env_missing if not p.startswith("@odata")]
            missing = [p for p in missing if not p.startswith("@odata")]
            # Graph's OpenAPI declares every property an entity *can* carry;
            # without $select the API returns a documented default subset, so
            # "missing" is not drift there. A property the spec never declares is.
            if extra or env_missing or env_extra or nested_extra:
                findings += (len(extra) + len(env_missing) + len(env_extra)
                             + len(nested_extra))
                print(f"  {method} {route}  ← {entry['spec']}")
                for p in env_missing:
                    print(f"      missing  {p}")
                for p in env_extra:
                    print(f"      extra    {p}")
                for p in extra[:15]:
                    print(f"      extra    value[*].{p}")
                for where, type_name, key in nested_extra[:15]:
                    print(f"      extra    {where}.{key}   "
                          f"({type_name} declares no such property)")
                if len(missing) > 15 or len(extra) > 15:
                    print(
                        f"      … {max(0, len(missing) - 15)} more missing, "
                        f"{max(0, len(extra) - 15)} more extra"
                    )
        print(f"\n{platform}: {checked} routes compared, {findings} drift findings")
        return 1 if findings else 0

    docs = load_specs(platform)
    spec_paths: dict[str, tuple[dict, str]] = {}
    for doc in docs:
        for p in doc.get("paths", {}):
            spec_paths[shape(p)] = (doc, p)
    for method, route in sorted(routes):
        if method != "GET":
            continue
        if route.startswith("/_dev/"):
            continue  # mockdr's own control surface, not the vendor's API
        if cfg.get("spec_prefix"):
            # The swagger carries the mount in its paths: match exactly, so
            # /policies is not judged by /upgrade-policy/policies.
            candidates = [k for k in spec_paths if k == shape(cfg["spec_prefix"] + route)]
        else:
            candidates = [
                k for k in spec_paths if k.endswith(shape(route)) or shape(route).endswith(k)
            ]
        if not candidates:
            print(f"  ?  {method} {route}: no spec path")
            continue
        doc, spec_path = spec_paths[max(candidates, key=len)]
        op = doc["paths"][spec_path].get(method.lower(), {})
        resp = op.get("responses", {}).get("200", {})
        schema = resp.get("schema") or resp.get("content", {}).get("application/json", {}).get(
            "schema", {}
        )
        declared = flatten(doc, schema)
        # Top-level members the spec declares but a success response omits
        # (SentinelOne's ``errors``).
        declared = {p for p in declared if p.split(".")[0] not in cfg.get("optional_top", ())}
        if not declared:
            continue
        url = _fill(client, route, headers, cfg.get("params", {}), cfg["fill"], mount)
        r = client.get(mount + url, headers=headers, params=cfg.get("params", {}))
        if r.status_code != 200:
            print(f"  -  {method} {route}: HTTP {r.status_code} (skipped)")
            continue
        body = r.json()
        seen = observed(body)
        unobservable = observed_opaque(body)
        free_form = declared_opaque(doc, schema)
        checked += 1
        # ARM polymorphism: a collection is typed as its base; each item's
        # `kind` names the derived definition whose properties it carries.
        base = base_name(doc, schema)
        items = body.get("value", [body]) if isinstance(body, dict) else []
        for item in (items if isinstance(items, list) else [])[:3]:
            kind = item.get("kind") if isinstance(item, dict) else None
            derived = derived_for_kind(doc, kind, base) if kind else None
            if derived:
                prefix = "value[*]." if "value" in body else ""
                declared |= flatten(doc, derived, prefix)
                free_form |= declared_opaque(doc, derived, prefix)
        # nextLink is declared but omitted by ARM when there is no next page:
        # its presence is pagination state, not shape, on either side.
        declared = {p for p in declared if p.split(".")[-1] != "nextLink"}
        seen = {p for p in seen if p.split(".")[-1] != "nextLink"}
        missing = sorted(
            p
            for p in declared
            if p not in seen and not p.endswith("[*]") and not _under(p, unobservable)
        )
        extra = sorted(
            p
            for p in seen
            if p not in declared and "[*]" not in p.split(".")[-1] and not _under(p, free_form)
        )
        if missing or extra:
            findings += len(missing) + len(extra)
            print(f"  {method} {route}  ← {spec_path}")
            for p in missing[:12]:
                print(f"      missing  {p}")
            for p in extra[:12]:
                print(f"      extra    {p}")
            if len(missing) > 12 or len(extra) > 12:
                print(
                    f"      … {max(0, len(missing) - 12)} more missing, "
                    f"{max(0, len(extra) - 12)} more extra"
                )
    print(f"\n{platform}: {checked} routes compared, {findings} drift findings")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1] if len(sys.argv) > 1 else "sentinel"))
