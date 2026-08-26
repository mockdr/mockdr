# ruff: noqa: ANN001, ANN201, ANN202, D103, E402
"""Reduce community OpenAPI files for the Cortex XDR API into a route → shape map.

Palo Alto publishes no machine-readable spec and its reference portal is
rendered client-side. ``github.com/tommynsong/cortex-mcp-custom-tools-openapi``
carries one OpenAPI 3 file per endpoint, transcribed from the official
reference. The repository has no licence, so the files are not vendored;
this reads a local clone and keeps only the facts — the key paths a 200
response declares, and the members its *request* marks required — in
``data/vendor-specs/xdr_openapi_reduced.json``. A transcription proves what
a real reply carries, not what it does not.

The request side is what stops a write route accepting a body that cannot be
what it meant: most Cortex routes require nothing at all (`xql/get_quota`
gives `{"request_data": null}` as its own example), and the few that do
require something are the only ones anything can be enforced for.

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


def request_facts(doc: dict, op: dict) -> dict:
    """What this operation's request body declares, if it declares anything.

    ``request_required`` is what the top level marks required — for Cortex
    that is ``request_data`` and nothing else — and ``request_data_required``
    what it marks required *inside* that wrapper. Most routes state neither,
    and those are left without either key rather than with an empty one: a
    silence is not a statement that nothing is required.
    """
    body = op.get("requestBody") or {}
    schema = ((body.get("content") or {}).get("application/json") or {}).get("schema")
    schema = deref(doc, schema or {})
    if not isinstance(schema, dict):
        return {}
    facts: dict[str, list[str]] = {}
    required = sorted(schema.get("required") or [])
    if required:
        facts["request_required"] = required
    wrapper = deref(doc, (schema.get("properties") or {}).get("request_data") or {})
    inner = sorted(wrapper.get("required") or []) if isinstance(wrapper, dict) else []
    if inner:
        facts["request_data_required"] = inner
    if facts:
        facts["request_paths"] = sorted(flatten(doc, schema))
    return facts


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
                entry = {"source": f.name, "paths": sorted(paths)}
                entry.update(request_facts(doc, op))
                reduced[key] = entry
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(f"{len(reduced)} routes → {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    # S108: the default is the clone path the module docstring documents, not a
    # file this script creates.
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/cortex-openapi")))  # noqa: S108
