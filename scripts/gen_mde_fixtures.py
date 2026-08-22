# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR2004
"""Generate default shapes for Defender for Endpoint resources from the docs.

Microsoft publishes no machine-readable MDE spec; ``scripts/mde_docs_spec.py``
reduces the docs tree to per-route example key paths and per-entity property
tables. This turns both into one default object per entity
(``backend/infrastructure/fixtures/mde/<entity>.json``): every property the
table names and every key the route's example shows, with type-correct
defaults, nested objects and arrays included. The serialisers deep-merge the
record over it.

    backend/.venv/bin/python scripts/gen_mde_fixtures.py
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REDUCED = ROOT / "data" / "vendor-specs" / "mde_docs_reduced.json"
OUT = ROOT / "backend" / "infrastructure" / "fixtures" / "mde"

#: entity -> (its table in the docs, the routes whose examples show it)
ENTITIES = {
    "machine": ("machine", ["GET /api/machines", "GET /api/machines/{id}"]),
    "alert": ("alerts", ["GET /api/alerts", "GET /api/alerts/{id}"]),
    "vulnerability": (
        "vulnerability",
        ["GET /api/vulnerabilities", "GET /api/vulnerabilities/{id}"],
    ),
    "machineaction": (
        "machineaction",
        [
            "GET /api/machineactions",
            "GET /api/machineactions/{id}",
            "POST /api/machines/{id}/isolate",
        ],
    ),
    "software": ("software", ["GET /api/software", "GET /api/software/{id}"]),
    "investigation": ("investigation", ["GET /api/investigations", "GET /api/investigations/{id}"]),
    "indicator": ("ti-indicator", ["GET /api/indicators"]),
    "file": ("files", ["GET /api/files/{id}"]),
    "user": (
        None,
        ["GET /api/users/{id}", "GET /api/machines/{id}/logonusers", "GET /api/alerts/{id}/user"],
    ),
}
#: docs tables spell a few keys differently from the API
_CASE = {
    "ID": "id",
    "Id": "id",
    "Evidence": "evidence",
    "Name": "name",
    "Description": "description",
    "Severity": "severity",
    "EPSS": "epss",
    "CveSupportability": "cveSupportability",
}


def _insert(tree: dict, path: str) -> None:
    """Create the nested default for a dotted path; ``x[*]`` is a list with one template item."""
    node = tree
    tokens = path.split(".")
    for i, token in enumerate(tokens):
        is_list = token.endswith("[*]")
        name = token[:-3] if is_list else token
        if not name:
            continue
        last = i == len(tokens) - 1
        if is_list:
            if not isinstance(node.get(name), list) or not node[name]:
                node[name] = [{}]
            if last:
                return
            node = node[name][0]
        elif last:
            node.setdefault(name, "")
        else:
            if not isinstance(node.get(name), dict):
                node[name] = {}
            node = node[name]


def _default_for_type(type_name: str):
    t = type_name.lower()
    if "bool" in t:
        return False
    if "int" in t or "long" in t or "double" in t or "number" in t:
        return 0
    if "list" in t or "collection" in t or "array" in t:
        return []
    if "object" in t or "dictionary" in t:
        return {}
    return ""


def main() -> int:
    doc = json.load(open(REDUCED))
    OUT.mkdir(parents=True, exist_ok=True)
    tables = doc.get("entities", {})
    routes = {k: dict(v) for k, v in doc.get("routes", {}).items()}
    # The XSOAR pack's recorded alert pages show fields the docs example elides.
    samples = REDUCED.with_name("mde_samples_reduced.json")
    if samples.exists():
        for key, entry in json.load(open(samples)).items():
            merged = routes.setdefault(key, {"page": "xsoar", "paths": []})
            merged["paths"] = sorted(set(merged["paths"]) | set(entry.get("paths", [])))
    for entity, (table, keys) in ENTITIES.items():
        tree: dict = {}
        for key in keys:
            for path in routes.get(key, {}).get("paths", []):
                if path.startswith("@odata") or path == "value":
                    continue
                if path.startswith("value[*]."):
                    path = path[len("value[*].") :]
                elif path.startswith("value"):
                    continue
                _insert(tree, _CASE.get(path, path))
        for prop in tables.get(table, []) if table else []:
            name = _CASE.get(prop, prop)
            tree.setdefault(name, "")
        tree = {k: v for k, v in tree.items() if k and k not in ("[]",)}
        (OUT / f"{entity}.json").write_text(json.dumps(tree, indent=1, sort_keys=True) + "\n")
        print(f"  {entity:14} {len(tree):3} keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
