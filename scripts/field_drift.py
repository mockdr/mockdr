#!/usr/bin/env python3
"""Field-drift detector: compares mock API responses against the Swagger 2.1 spec.

Exits 0 if every monitored endpoint returns exactly the fields the spec defines.
Exits 1 if any endpoint has missing or extra fields.

Usage:
    python scripts/field_drift.py
    python scripts/field_drift.py --base-url http://localhost:8001/web/api/v2.1
    python scripts/field_drift.py --start-server   # auto-start uvicorn, then check
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import requests

# ── Configuration ────────────────────────────────────────────────────────────

SWAGGER_PATH = Path(__file__).resolve().parent.parent / "data" / "swagger_2_1.json"

# Endpoints to monitor: friendly name -> (swagger path, mock path, data_layout)
# data_layout:
#   "list"   -> response.data is a list of items
#   "sites"  -> response.data.sites is a list, data.allSites is an object
# Fields intentionally different between mock and spec.  Each entry
# suppresses drift for a dotted key path — document *why* it's expected.
KNOWN_EXCEPTIONS: dict[str, set[str]] = {
    # Mock doesn't populate activeDirectory.mail (not in real agent data we tested)
    "agents": {"activeDirectory.mail"},
    # Mock omits indicators[].categoryId; adds agentComputerName per real S1 API
    "threats": {
        "indicators[].categoryId",
        "agentDetectionInfo.agentComputerName",
    },
    # Mock scope is {tenant: true}; spec defines sub-arrays we don't populate
    "exclusions": {
        "scope.accountIds",
        "scope.groupIds",
        "scope.siteIds",
    },
    # productId not applicable in our seed data
    "firewall": {"productId"},
    # Mock adds agentRealtimeInfo for integration compatibility (not in spec for alerts)
    "alerts": {
        "agentRealtimeInfo.accountId",
        "agentRealtimeInfo.agentComputerName",
        "agentRealtimeInfo.agentVersion",
        "agentRealtimeInfo.id",
        "agentRealtimeInfo.os",
        "agentRealtimeInfo.siteId",
        "agentRealtimeInfo.siteName",
    },
}

ENDPOINTS: dict[str, tuple[str, str, str]] = {
    "agents":           ("/web/api/v2.1/agents",                    "/agents",                    "list"),
    "threats":          ("/web/api/v2.1/threats",                   "/threats",                   "list"),
    "sites":            ("/web/api/v2.1/sites",                     "/sites",                     "sites"),
    "groups":           ("/web/api/v2.1/groups",                    "/groups",                    "list"),
    "exclusions":       ("/web/api/v2.1/exclusions",                "/exclusions",                "list"),
    "users":            ("/web/api/v2.1/users",                     "/users",                     "list"),
    "firewall":         ("/web/api/v2.1/firewall-control",          "/firewall-control",          "list"),
    "alerts":           ("/web/api/v2.1/cloud-detection/alerts",    "/cloud-detection/alerts",    "list"),
    "activities":       ("/web/api/v2.1/activities",                "/activities",                "list"),
    "device-control":   ("/web/api/v2.1/device-control",            "/device-control",            "list"),
    "iocs":             ("/web/api/v2.1/threat-intelligence/iocs",  "/threat-intelligence/iocs",  "list"),
    "restrictions":     ("/web/api/v2.1/restrictions",              "/restrictions",              "list"),
}


# ── Swagger helpers ──────────────────────────────────────────────────────────

def load_spec() -> dict[str, Any]:
    with open(SWAGGER_PATH) as f:
        return json.load(f)


def _resolve_ref(spec: dict[str, Any], ref: str) -> dict[str, Any]:
    """Resolve a $ref like '#/definitions/Foo' into the definition dict."""
    name = ref.removeprefix("#/definitions/")
    return spec["definitions"].get(name, {})


def _get_schema_node(
    spec: dict[str, Any],
    schema: dict[str, Any],
    field_name: str,
) -> dict[str, Any] | None:
    """Look up a field's schema definition within a parent schema."""
    props = schema.get("properties", {})
    field_def = props.get(field_name)
    if field_def is None:
        return None
    if "$ref" in field_def:
        return _resolve_ref(spec, field_def["$ref"])
    return field_def


def extract_keys_from_schema(
    spec: dict[str, Any],
    schema: dict[str, Any],
    prefix: str = "",
) -> set[str]:
    """Recursively extract dotted key paths from a Swagger schema."""
    keys: set[str] = set()
    props = schema.get("properties", {})
    for field_name, field_def in props.items():
        full = f"{prefix}.{field_name}" if prefix else field_name

        if "$ref" in field_def:
            resolved = _resolve_ref(spec, field_def["$ref"])
            keys.update(extract_keys_from_schema(spec, resolved, full))
        elif field_def.get("type") == "object" and "properties" in field_def:
            keys.update(extract_keys_from_schema(spec, field_def, full))
        elif field_def.get("type") == "array" and "items" in field_def:
            items = field_def["items"]
            if "$ref" in items:
                resolved = _resolve_ref(spec, items["$ref"])
                keys.update(extract_keys_from_schema(spec, resolved, f"{full}[]"))
            elif items.get("type") == "object" and "properties" in items:
                keys.update(extract_keys_from_schema(spec, items, f"{full}[]"))
            else:
                keys.add(full)
        else:
            keys.add(full)
    return keys


def get_item_schema(spec: dict[str, Any], swagger_path: str, data_layout: str) -> dict[str, Any]:
    """Return the schema dict for a single item in the endpoint's data array."""
    path_obj = spec["paths"].get(swagger_path, {})
    get_op = path_obj.get("get", {})
    ok_resp = get_op.get("responses", {}).get("200", {})
    schema = ok_resp.get("schema", {})

    if "$ref" in schema:
        schema = _resolve_ref(spec, schema["$ref"])

    data_prop = schema.get("properties", {}).get("data", {})
    if not data_prop:
        return {}

    if data_layout == "sites":
        # sites data is an inline object with allSites + sites[]
        if data_prop.get("type") == "object" and "properties" in data_prop:
            return data_prop
        return {}

    # "list" layout: data is array of items
    if data_prop.get("type") == "array" and "items" in data_prop:
        items = data_prop["items"]
        if "$ref" in items:
            return _resolve_ref(spec, items["$ref"])
        return items

    if "$ref" in data_prop:
        return _resolve_ref(spec, data_prop["$ref"])

    return {}


def get_spec_keys(spec: dict[str, Any], swagger_path: str, data_layout: str) -> set[str]:
    """Return the set of dotted field paths for a GET endpoint's 200 response."""
    item_schema = get_item_schema(spec, swagger_path, data_layout)
    if not item_schema:
        return set()
    return extract_keys_from_schema(spec, item_schema)


# ── Mock response helpers ────────────────────────────────────────────────────

def extract_keys_from_value(
    spec: dict[str, Any],
    value: Any,
    parent_schema: dict[str, Any],
    prefix: str = "",
) -> set[str]:
    """Recursively extract dotted key paths from a live JSON value.

    When the mock returns None or [] for a field that the spec defines as an
    object or array-of-objects, we fall back to the spec to emit the leaf keys.
    This prevents false-positive "missing" reports for nullable nested objects.
    """
    keys: set[str] = set()
    if not isinstance(value, dict):
        return keys

    for k, v in value.items():
        full = f"{prefix}.{k}" if prefix else k
        field_schema = _get_schema_node(spec, parent_schema, k)

        if isinstance(v, dict) and v:
            # Recurse into populated dict
            child_schema = field_schema if field_schema and "properties" in field_schema else {"properties": {}}
            keys.update(extract_keys_from_value(spec, v, child_schema, full))

        elif isinstance(v, list) and v and isinstance(v[0], dict):
            # Recurse into first item of populated list
            items_schema: dict[str, Any] = {}
            if field_schema:
                items = field_schema.get("items", {})
                if "$ref" in items:
                    items_schema = _resolve_ref(spec, items["$ref"])
                elif "properties" in items:
                    items_schema = items
            keys.update(extract_keys_from_value(spec, v[0], items_schema, f"{full}[]"))

        elif v is None and field_schema:
            # Null value — check if spec says this should be an object
            fs_type = field_schema.get("type")
            if fs_type == "object" and "properties" in field_schema:
                # Emit spec keys since mock is null
                keys.update(extract_keys_from_schema(spec, field_schema, full))
            elif "$ref" in field_schema:
                resolved = _resolve_ref(spec, field_schema["$ref"])
                if resolved.get("properties"):
                    keys.update(extract_keys_from_schema(spec, resolved, full))
                else:
                    keys.add(full)
            else:
                keys.add(full)

        elif isinstance(v, list) and not v and field_schema:
            # Empty list — check if spec says items are objects
            items = field_schema.get("items", {})
            if "$ref" in items:
                resolved = _resolve_ref(spec, items["$ref"])
                if resolved.get("properties"):
                    keys.update(extract_keys_from_schema(spec, resolved, f"{full}[]"))
                else:
                    keys.add(full)
            elif items.get("type") == "object" and "properties" in items:
                keys.update(extract_keys_from_schema(spec, items, f"{full}[]"))
            else:
                keys.add(full)

        elif isinstance(v, dict) and not v and field_schema:
            # Empty dict — use spec to fill in expected keys
            if "properties" in field_schema:
                keys.update(extract_keys_from_schema(spec, field_schema, full))
            else:
                keys.add(full)

        else:
            keys.add(full)

    return keys


def get_mock_keys(
    spec: dict[str, Any],
    base_url: str,
    mock_path: str,
    token: str,
    data_layout: str,
    item_schema: dict[str, Any],
) -> set[str]:
    """Fetch a GET endpoint and return dotted key paths from the first item."""
    url = f"{base_url}{mock_path}"
    headers = {"Authorization": f"ApiToken {token}"}
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    body = resp.json()
    data = body.get("data")

    if data_layout == "sites":
        # sites has {data: {allSites: {...}, sites: [...]}}
        if isinstance(data, dict):
            return extract_keys_from_value(spec, data, item_schema)
        return set()

    # "list" layout: data is a list
    if isinstance(data, list) and data:
        return extract_keys_from_value(spec, data[0], item_schema)

    return set()


# ── Server management ────────────────────────────────────────────────────────

def wait_for_server(base_url: str, timeout: int = 30) -> bool:
    """Wait until the server is reachable."""
    deadline = time.time() + timeout
    status_url = base_url.rstrip("/").rsplit("/web/api/v2.1", 1)[0]
    status_url += "/web/api/v2.1/system/status"
    while time.time() < deadline:
        try:
            r = requests.get(status_url, timeout=2)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    return False


def start_server() -> subprocess.Popen[bytes]:
    """Start the backend server as a subprocess."""
    backend_dir = Path(__file__).resolve().parent.parent / "backend"
    proc = subprocess.Popen(
        [
            sys.executable, "-m", "uvicorn",
            "main:app",
            "--host", "0.0.0.0",
            "--port", "8001",
        ],
        cwd=str(backend_dir),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


# ── Reconciliation ───────────────────────────────────────────────────────────

def _reconcile(spec_keys: set[str], mock_keys: set[str]) -> tuple[set[str], set[str]]:
    """Compute true missing/extra sets, accounting for depth mismatches.

    When the spec defines a field as a simple leaf (e.g. "application") but the
    mock returns it as an object with sub-fields ("application.type",
    "application.values"), the mock is providing *more* detail — not drifting.
    Similarly, when the mock returns a null/empty value for a spec-defined
    nested object, the spec sub-keys are covered by the mock's parent key.
    """
    raw_missing = spec_keys - mock_keys
    raw_extra = mock_keys - spec_keys

    # A spec leaf "foo" is satisfied if mock has any key starting with "foo."
    resolved_missing: set[str] = set()
    for sk in raw_missing:
        prefix = sk + "."
        prefix_arr = sk + "["
        if any(mk.startswith(prefix) or mk.startswith(prefix_arr) for mk in mock_keys):
            continue  # mock expanded this leaf into sub-keys
        resolved_missing.add(sk)

    # A mock key "foo.bar" is tolerated if spec has "foo" as a leaf
    resolved_extra: set[str] = set()
    for mk in raw_extra:
        parts = mk.split(".")
        # Check all ancestor prefixes: foo.bar.baz -> foo, foo.bar
        covered = False
        for i in range(1, len(parts)):
            ancestor = ".".join(parts[:i])
            # Strip trailing [] for array ancestors
            ancestor_clean = ancestor.rstrip("[]")
            if ancestor_clean in spec_keys or ancestor in spec_keys:
                covered = True
                break
        if not covered:
            resolved_extra.add(mk)

    return resolved_missing, resolved_extra


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Detect field drift between mock API and Swagger spec")
    parser.add_argument(
        "--base-url",
        default="http://localhost:8001/web/api/v2.1",
        help="Base URL of the mock API (default: http://localhost:8001/web/api/v2.1)",
    )
    parser.add_argument(
        "--token",
        default="admin-token-0000-0000-000000000001",
        help="API token for authentication",
    )
    parser.add_argument(
        "--start-server",
        action="store_true",
        help="Auto-start the backend server before checking",
    )
    args = parser.parse_args()

    server_proc = None
    if args.start_server:
        print("Starting backend server...")
        server_proc = start_server()

    try:
        print(f"Waiting for server at {args.base_url} ...")
        if not wait_for_server(args.base_url):
            print("ERROR: Server did not become ready within 30 seconds.")
            return 1
        print("Server is ready.\n")

        spec = load_spec()
        has_drift = False
        total_endpoints = 0
        clean_endpoints = 0

        for name, (swagger_path, mock_path, layout) in ENDPOINTS.items():
            total_endpoints += 1
            item_schema = get_item_schema(spec, swagger_path, layout)
            spec_keys = get_spec_keys(spec, swagger_path, layout)
            if not spec_keys:
                print(f"  WARN  {name}: no spec keys found for {swagger_path} (skipping)")
                continue

            try:
                mock_keys = get_mock_keys(
                    spec, args.base_url, mock_path, args.token, layout, item_schema,
                )
            except requests.HTTPError as exc:
                print(f"  FAIL  {name}: HTTP {exc.response.status_code} from {mock_path}")
                has_drift = True
                continue
            except Exception as exc:
                print(f"  FAIL  {name}: {exc}")
                has_drift = True
                continue

            if not mock_keys:
                print(f"  WARN  {name}: empty response from {mock_path} (no items?)")
                continue

            # Reconcile: if spec has "foo" as a leaf but mock expands it to
            # "foo.bar", "foo.baz" — the mock is more detailed, not drifting.
            # Also: if mock has "foo" as a leaf but spec expands it to
            # "foo.bar" — the mock is less detailed (nullable/empty).
            missing, extra = _reconcile(spec_keys, mock_keys)

            known = KNOWN_EXCEPTIONS.get(name, set())
            missing -= known
            extra -= known

            if missing or extra:
                has_drift = True
                print(f"  DRIFT {name}:")
                if missing:
                    for k in sorted(missing):
                        print(f"         - MISSING (in spec, not in mock): {k}")
                if extra:
                    for k in sorted(extra):
                        print(f"         + EXTRA   (in mock, not in spec): {k}")
            else:
                clean_endpoints += 1
                print(f"  OK    {name} ({len(spec_keys)} spec fields matched)")

        print()
        print(f"Results: {clean_endpoints}/{total_endpoints} endpoints clean")

        if has_drift:
            print("\nFAILED: field drift detected. Fix the mock or update the spec.")
            return 1

        print("\nPASSED: no field drift detected.")
        return 0

    finally:
        if server_proc:
            server_proc.terminate()
            server_proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
