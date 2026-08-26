# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Find an answer whose value is outside the set the vendor declares.

A field of the right name and the right type can still carry a value no
client will recognise: a status a switch statement has no branch for, a
severity a dashboard cannot colour. `field_drift.py` compares which fields
are answered and `schema_drift.py` compares their types; neither reads the
values, and a mock that invents `"Critical"` where the vendor writes
`"high"` passes both.

Two dialects are read, and both have to be read per *type* rather than per
field name — the same name carries different sets on different objects. A
Graph security alert's `status` is `unknown | new | inProgress | resolved`
while an incident's is `active | awaitingAction | inProgress | redirected |
resolved`; keying by the name alone reports every alert in this install as
wrong. The same goes for SentinelOne, where `value` is a network interface's
connection type on one schema and a tag's text on another.

    backend/.venv/bin/python scripts/enum_drift.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import json
import logging
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "data" / "swagger_2_1.json"
CSDL = ROOT / "data" / "vendor-specs" / "graph_v1.0_csdl_types.json"

#: SentinelOne collections whose 200 the swagger describes, and how the
#: records sit in the envelope.
_S1_ROUTES = (
    ("/web/api/v2.1/agents", "data"),
    ("/web/api/v2.1/threats", "data"),
    ("/web/api/v2.1/groups", "data"),
    ("/web/api/v2.1/exclusions", "data"),
    ("/web/api/v2.1/restrictions", "data"),
    ("/web/api/v2.1/users", "data"),
    ("/web/api/v2.1/activities", "data"),
    ("/web/api/v2.1/firewall-control", "data"),
    ("/web/api/v2.1/device-control", "data"),
    ("/web/api/v2.1/cloud-detection/alerts", "data"),
    ("/web/api/v2.1/cloud-detection/rules", "data"),
    ("/web/api/v2.1/sites", "data.sites"),
)

#: Graph entity types this mock serves, and where.
_GRAPH_TYPES = (
    ("/graph/v1.0/security/alerts_v2", "microsoft.graph.security.alert"),
    ("/graph/v1.0/security/incidents", "microsoft.graph.security.incident"),
)

S1_HEADERS = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def resolve(schema, definitions, seen=()):
    """A schema with its `$ref` followed, stopping at a cycle."""
    if isinstance(schema, dict) and "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        if name in seen:
            return {}
        return resolve(definitions.get(name, {}), definitions, (*seen, name))
    return schema or {}


def swagger_enums(schema, definitions, path="", found=None, seen=()):
    """Every enumerated field of a response schema, by its path in an item."""
    found = {} if found is None else found
    schema = resolve(schema, definitions, seen)
    if not isinstance(schema, dict):
        return found
    if schema.get("enum"):
        found[path] = {str(v) for v in schema["enum"]}
    for key, sub in (schema.get("properties") or {}).items():
        swagger_enums(sub, definitions, f"{path}.{key}" if path else key, found, seen)
    if "items" in schema:
        swagger_enums(schema["items"], definitions, f"{path}[]", found, seen)
    return found


def csdl_enums(types, type_name):
    """Every property of a CSDL type whose value comes from an enum."""
    members = {
        name: set(entry["members"])
        for name, entry in types.items()
        if entry.get("kind") == "EnumType"
    }
    entry = types.get(type_name, {})
    namespace = entry.get("namespace", "")
    found = {}
    for prop, declared in (entry.get("properties") or {}).items():
        base = str(declared).replace("Collection(", "").rstrip(")").replace(
            "self.", f"{namespace}.")
        if base in members:
            found[prop] = members[base]
    return found


def offences(item, allowed, prefix=""):
    """Every value of `item` that its schema does not allow."""
    found = []
    if isinstance(item, dict):
        for key, value in item.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, str) and value and path in allowed:
                if value not in allowed[path]:
                    found.append((path, value, sorted(allowed[path])))
            else:
                found.extend(offences(value, allowed, path))
    elif isinstance(item, list):
        for element in item:
            found.extend(offences(element, allowed, f"{prefix}[]"))
    return found


def walk(body, layout):
    """The records of an answer, whatever envelope they arrive in."""
    node = body
    for key in layout.split("."):
        node = node.get(key) if isinstance(node, dict) else None
    return node if isinstance(node, list) else []


def main():
    """Report every answered value outside the set its vendor declares."""
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    spec = json.loads(SWAGGER.read_text())
    definitions = spec["definitions"]
    types = json.loads(CSDL.read_text())

    flags, checked = [], 0
    with TestClient(app) as client:
        for path, layout in _S1_ROUTES:
            operation = spec["paths"].get(path, {}).get("get")
            if not operation:
                continue
            allowed = swagger_enums(
                operation.get("responses", {}).get("200", {}).get("schema"), definitions,
            )
            item_enums = {
                key[len("data[]."):]: value
                for key, value in allowed.items()
                if key.startswith("data[].")
            }
            if not item_enums:
                continue
            checked += len(item_enums)
            answer = client.get(path, headers=S1_HEADERS, params={"limit": 100})
            for record in walk(answer.json(), layout):
                for field, value, expected in offences(record, item_enums):
                    flags.append((path, field, value, expected))

        token = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }).json().get("access_token", "")
        headers = {"Authorization": f"Bearer {token}"}
        for path, type_name in _GRAPH_TYPES:
            allowed = csdl_enums(types, type_name)
            checked += len(allowed)
            for record in client.get(path, headers=headers).json().get("value", []):
                for field, values in allowed.items():
                    value = record.get(field)
                    if isinstance(value, str) and value and value not in values:
                        flags.append((path, field, value, sorted(values)))

    print(f"=== ENUM DRIFT === {checked} enumerated field(s) read")
    seen = set()
    for path, field, value, expected in flags:
        if (path, field, value) in seen:
            continue
        seen.add((path, field, value))
        print(f"  {path} {field}: {value!r} is not one of {expected}")
    print(f"\n  {len(seen)} value(s) the vendor does not declare")
    return 1 if seen else 0


if __name__ == "__main__":
    sys.exit(main())
