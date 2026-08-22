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
        "crowdstrike": [SPECS / "crowdstrike_swagger.json"],
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
            out |= declared_opaque(doc, sub.get("items", {}), f"{path}[*].", depth + 1)
        elif "properties" in sub or "allOf" in sub:
            out |= declared_opaque(doc, sub, f"{path}.", depth + 1)
        elif sub.get("type") == "object" or "additionalProperties" in sub:
            out.add(path)
    return out


def _under(path: str, prefixes: set[str]) -> bool:
    return any(path == o or path.startswith(o + ".") or path.startswith(o + "[") for o in prefixes)


@functools.cache
def _graph_types() -> dict:
    path = SPECS / "graph_v1.0_types.json"
    return json.load(open(path)) if path.exists() else {}


def graph_type_props(type_name: str) -> set[str]:
    """The properties graph_v1.0_types.json declares for ``microsoft.graph.X``."""
    entry = _graph_types().get(type_name)
    if isinstance(entry, dict):
        return set(entry.get("properties", entry))
    return set(entry or [])


def shape(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path.lower())


PLATFORMS = {
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
    items = body.get("value") if isinstance(body, dict) else body
    out = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        ident = item.get("id")
        if not isinstance(ident, str) or "/" in ident:
            ident = item.get("name") or item.get("alias") or ident
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
    if "reduced" in cfg:
        reduced = json.load(open(cfg["reduced"]))
        for key, entry in sorted(reduced.items()):
            if not entry.get("spec"):
                continue
            method, route = key.split(" ", 1)
            if method != "GET":
                continue
            if route.startswith("/beta/"):
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
            if extra or env_missing or env_extra:
                findings += len(extra) + len(env_missing) + len(env_extra)
                print(f"  {method} {route}  ← {entry['spec']}")
                for p in env_missing:
                    print(f"      missing  {p}")
                for p in env_extra:
                    print(f"      extra    {p}")
                for p in extra[:15]:
                    print(f"      extra    value[*].{p}")
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
        candidates = [k for k in spec_paths if k.endswith(shape(route)) or shape(route).endswith(k)]
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
