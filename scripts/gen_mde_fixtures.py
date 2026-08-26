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
            "POST /api/machines/{id}/runliveresponse",
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


def _recorded_types() -> dict[str, str]:
    """The leaf types a recorded reply was seen holding.

    The docs give a type for the fields their tables list and none for the
    ones that only appear in an example — so every member of `evidence` was
    defaulted to a string, including `processId`, which a real reply carries
    as a number. A recorded reply settles it where the table is silent.
    """
    recorded = REDUCED.with_name("splunk_ta_samples_reduced.json")
    if not recorded.exists():
        return {}
    out: dict[str, str] = {}
    for entry in json.load(open(recorded)).values():
        out.update(entry.get("types") or {})
        # A field the reply was seen leaving empty defaults to null, whatever
        # type its populated values had.
        for path in entry.get("nullable") or []:
            out[path] = "null"
    return out


_FROM_TYPE: dict[str, object] = {
    "number": 0, "boolean": False, "array": [], "object": {}, "string": "",
    "null": None,
}


def _apply_types(tree: dict, observed: dict[str, str], prefix: str = "") -> None:
    """Replace a guessed default with the type a real reply was seen holding."""
    for key, value in tree.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            _apply_types(value, observed, f"{path}.")
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            _apply_types(value[0], observed, f"{path}[*].")
        else:
            kind = observed.get(path)
            if kind is None or kind not in _FROM_TYPE:
                continue
            wanted = _FROM_TYPE[kind]
            if wanted is None or not isinstance(value, type(wanted)):
                tree[key] = wanted


def main() -> int:
    doc = json.load(open(REDUCED))
    observed = _recorded_types()
    OUT.mkdir(parents=True, exist_ok=True)
    tables = doc.get("entities", {})
    # the docs spell paths with their own casing (/API/machines/…)
    routes = {k.lower(): dict(v) for k, v in doc.get("routes", {}).items()}
    # The XSOAR pack's recorded alert pages show fields the docs example elides.
    samples = REDUCED.with_name("mde_samples_reduced.json")
    if samples.exists():
        for key, entry in json.load(open(samples)).items():
            merged = routes.setdefault(key.lower(), {"page": "xsoar", "paths": []})
            merged["paths"] = sorted(set(merged["paths"]) | set(entry.get("paths", [])))
    for entity, (table, keys) in ENTITIES.items():
        tree: dict = {}
        for key in keys:
            for path in routes.get(key.lower(), {}).get("paths", []):
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
        _apply_types(tree, observed)
        (OUT / f"{entity}.json").write_text(json.dumps(tree, indent=1, sort_keys=True) + "\n")
        print(f"  {entity:14} {len(tree):3} keys")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
