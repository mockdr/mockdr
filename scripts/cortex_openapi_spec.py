# ruff: noqa: ANN001, ANN201, ANN202, D103, E402
"""Reduce community OpenAPI files for the Cortex XDR API into a route → shape map.

Palo Alto publishes no machine-readable spec and its reference portal is
rendered client-side. ``github.com/tommynsong/cortex-mcp-custom-tools-openapi``
carries one OpenAPI 3 file per endpoint, transcribed from the official
reference. The repository has no licence, so the files are not vendored;
this reads a local clone and keeps only the facts — the key paths a 200
response declares — in ``data/vendor-specs/xdr_openapi_reduced.json``. A
transcription proves what a real reply carries, not what it does not.

    git clone --depth 1 \
        https://github.com/tommynsong/cortex-mcp-custom-tools-openapi \
        /tmp/cortex-openapi
    backend/.venv/bin/python scripts/cortex_openapi_spec.py /tmp/cortex-openapi
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "xdr_openapi_reduced.json"


def deref(doc: dict, node):
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        target = doc
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        node = target
        seen += 1
    return node


def flatten(doc: dict, schema, prefix: str = "", depth: int = 0) -> set[str]:
    out: set[str] = set()
    schema = deref(doc, schema)
    if depth > 7 or not isinstance(schema, dict):
        return out
    for name, sub in (schema.get("properties") or {}).items():
        path = f"{prefix}{name}"
        out.add(path)
        sub = deref(doc, sub)
        if not isinstance(sub, dict):
            continue
        if sub.get("type") == "array":
            out |= flatten(doc, sub.get("items", {}), f"{path}[*].", depth + 1)
        else:
            out |= flatten(doc, sub, f"{path}.", depth + 1)
    for part in schema.get("allOf") or []:
        out |= flatten(doc, part, prefix, depth + 1)
    return out


def main(clone: Path) -> int:
    reduced: dict[str, dict] = {}
    for f in sorted(clone.glob("*.yaml")):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for path, methods in (doc.get("paths") or {}).items():
            for method, op in methods.items():
                resp = (
                    (op.get("responses") or {}).get("200")
                    or (op.get("responses") or {}).get(200)
                    or {}
                )
                schema = ((resp.get("content") or {}).get("application/json") or {}).get("schema")
                if not schema:
                    continue
                paths = flatten(doc, schema)
                key = f"{method.upper()} {path}"
                reduced[key] = {"source": f.name, "paths": sorted(paths)}
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(f"{len(reduced)} routes → {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    # S108: the default is the clone path the module docstring documents, not a
    # file this script creates.
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/cortex-openapi")))  # noqa: S108
