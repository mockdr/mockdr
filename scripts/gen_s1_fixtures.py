# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004
"""Generate type-correct default shapes for SentinelOne responses from the swagger.

The Management API 2.1 swagger (``data/swagger_2_1.json``, fetched by
``scripts/fetch_swagger.sh``) is generated from the product's own response
schemas, so every property it declares is one a real response carries. For
each GET route the mock mounts, this resolves the 200 response's ``data``
schema and writes a default object — "" / 0 / false / [] / nested objects —
to ``backend/infrastructure/fixtures/sentinelone/<definition>.json``; the
builders deep-merge their values over it.

    backend/.venv/bin/python scripts/gen_s1_fixtures.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "backend"))
from schema_drift import deref, props  # noqa: E402

SWAGGER = ROOT / "data" / "swagger_2_1.json"
OUT = ROOT / "backend" / "infrastructure" / "fixtures" / "sentinelone"
MOUNT = "/web/api/v2.1"


def default_for(doc: dict, schema, depth: int = 0):
    """A type-correct default; an array of objects carries one template item.

    The completion helper treats a list in the fixture as the template for
    the items a record provides (and [] when it provides none), so nested
    object lists — ``sites[*].irFields`` — are declared all the way down.
    """
    schema = deref(doc, schema)
    if depth > 7 or not isinstance(schema, dict):
        return None
    kind = schema.get("type")
    if "properties" in schema or "allOf" in schema or kind == "object":
        return {
            name: default_for(doc, sub, depth + 1)
            for name, sub in props(doc, schema, depth).items()
        }
    if kind == "array":
        item = default_for(doc, schema.get("items", {}), depth + 1)
        return [item] if isinstance(item, dict) and item else []
    # The swagger says where the product answers null (``x-nullable``); every
    # other scalar is typed, so a client's schema check passes.
    if schema.get("x-nullable"):
        return None
    # The vendor's own example is the most faithful typed default (it also
    # satisfies the swagger's patterns, e.g. an e-mail).
    if "example" in schema and kind in ("string", "integer", "number", "boolean"):
        example = schema["example"]
        pattern = schema.get("pattern")
        if isinstance(example, str) and pattern and not re.search(pattern, example):
            # The swagger's e-mail pattern is upper-case only (a lost
            # IGNORECASE); its own example matches only upper-cased.
            if re.search(pattern, example.upper()):
                return example.upper()
        return example
    if kind == "boolean":
        return False
    if kind in ("integer", "number"):
        return 0
    if kind == "string":
        return "" if "enum" not in schema else schema["enum"][0]
    return None


def main() -> int:
    import logging
    import warnings

    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    from main import app  # noqa: PLC0415

    doc = json.load(open(SWAGGER))
    OUT.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}
    for path, methods in app.openapi()["paths"].items():
        if not path.startswith(MOUNT + "/") or "get" not in methods:
            continue
        route = path[len(MOUNT) :]
        op = doc["paths"].get(MOUNT + route, {}).get("get")
        if not op:
            continue
        ref = op.get("responses", {}).get("200", {}).get("schema", {}).get("$ref", "")
        name = ref.rsplit("/", 1)[-1]
        if not name or name in written:
            if name:
                written[name] += f", {route}"
            continue
        schema = deref(doc, {"$ref": ref})
        data_schema = schema.get("properties", {}).get("data") if isinstance(schema, dict) else None
        if data_schema is None:
            continue
        data_schema = deref(doc, data_schema)
        if data_schema.get("type") == "array":
            shape = {"data": [default_for(doc, data_schema.get("items", {}))]}
        else:
            shape = {"data": default_for(doc, data_schema)}
        fixture = {"definition": name, "routes": route, **shape}
        (OUT / f"{name}.json").write_text(json.dumps(fixture, indent=1, ensure_ascii=False) + "\n")
        written[name] = route
    for name, routes in sorted(written.items()):
        print(f"  {name:60} {routes}")
    print(f"{len(written)} fixtures → {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
