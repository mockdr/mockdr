"""Derive the filters the SentinelOne swagger declares, for the fields we have.

`param_drift.py` counts what the vendor documents and this mock does not
take. Most of those are mechanical variants of one field —
`computerName__contains`, `activeThreats__gt`, `createdAt__between` — and a
mock that lists the same records can apply them. This reads the 2.1 swagger,
keeps every documented parameter whose base name is a field the mock's own
response carries, and writes them as filter specs:

    backend/application/documented_filters.py

Nothing is guessed: a parameter whose field the record does not have is left
out and stays in the drift count. The suffix decides the operator, the
swagger's declared type decides how the value is read, and an enum-typed
parameter is matched in both the spelling the API takes and the one it
answers.

    backend/.venv/bin/python scripts/gen_documented_filters.py
"""

from __future__ import annotations

import json
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "data" / "swagger_2_1.json"
OUT = ROOT / "backend" / "application" / "documented_filters.py"
PREFIX = "/web/api/v2.1"

#: Suffix → filter strategy. Order matters: the longest match wins.
#: An ISO-8601 date this mock's own records carry, as its answers spell them.
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}:\d{2}|$)")

#: ruff's limit for the file this writes.
LINE_LIMIT = 100

SUFFIX_OPS: list[tuple[str, str]] = [
    ("__contains", "contains"),
    ("__between", "between"),
    ("__gte", "gte"),
    ("__lte", "lte"),
    ("__gt", "gt"),
    ("__lt", "lt"),
    ("__nin", "nin"),
    ("__in", "in"),
    ("Nin", "nin"),
]

#: Parameters that decide the shape of the answer rather than narrow it.
NOT_FILTERS = {
    "limit", "cursor", "skip", "skipCount", "countOnly", "sortBy", "sortOrder",
    "tenant", "ids", "query", "includeChildren", "includeParents",
}


def _operator(name: str) -> tuple[str, str]:
    """The parameter's base field name and the strategy its suffix names."""
    for suffix, op in SUFFIX_OPS:
        if name.endswith(suffix) and len(name) > len(suffix):
            return name[: -len(suffix)], op
    return name, ""


def _field_paths(value: object, prefix: str = "", depth: int = 0) -> dict[str, str]:
    """Map each field name a sample response carries to its dot-path."""
    found: dict[str, str] = {}
    if depth > 3:
        return found
    if isinstance(value, dict):
        for key, sub in value.items():
            path = f"{prefix}{key}"
            found.setdefault(key, path)
            found[path] = path
            found.update(_field_paths(sub, f"{path}.", depth + 1))
    elif isinstance(value, list) and value:
        found.update(_field_paths(value[0], prefix, depth + 1))
    return found


def _records(body: object) -> list[dict]:
    """Every record of a list response, whatever envelope it wears."""
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return [r for r in value if isinstance(r, dict)]
    return []


def _is_dated(declared: dict, records: list[dict], field: str, op: str) -> bool:
    """Whether this parameter compares timestamps, on evidence rather than name.

    Two sources, and neither is the parameter's spelling: the swagger declares
    `format: date-time` on 20 of them, and for the rest the mock's own answer
    is the evidence — a field whose sampled value is an ISO-8601 timestamp is
    compared as one. A parameter that does not order anything (`eq`,
    `contains`, `in`) is left alone: refusing a substring for not being a
    timestamp would be a new wrongness in place of the old one.
    """
    if op not in ("gt", "gte", "lt", "lte", "between", "gte_dt", "lte_dt"):
        return False
    if declared.get("format") == "date-time":
        return True
    return any(_ISO_DATE.match(v) for v in (_value(r, field) for r in records) if v)


def _value(record: dict, field: str) -> str | None:
    """The record's value at a dot-path, when it is a string."""
    value: object = record
    for part in field.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
        if isinstance(value, list) and value:
            value = value[0]
    return value if isinstance(value, str) else None


def _sample(body: object) -> dict | None:
    """The first record of a list response, whatever envelope it wears."""
    data = body.get("data") if isinstance(body, dict) else None
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return data[0]
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value[0]
    return None


def main() -> int:
    """Write the derived filter specs and report the coverage."""
    if not SWAGGER.exists():
        print(f"{SWAGGER.relative_to(ROOT)} is missing — run scripts/fetch_swagger.sh")
        return 2

    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from application.documented_filters import DOCUMENTED_FILTERS  # noqa: PLC0415
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    spec = json.loads(SWAGGER.read_text())
    mock = app.openapi()
    headers = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

    derived: dict[str, list[tuple[str, str, str, bool, str]]] = {}
    skipped = 0
    with TestClient(app) as client:
        for path, operations in sorted(spec["paths"].items()):
            if "{" in path or path not in mock["paths"] or "get" not in operations:
                continue
            mocked_op = mock["paths"][path].get("get")
            if mocked_op is None:
                continue
            documented = {
                p["name"]: p
                for p in operations["get"].get("parameters", [])
                if p.get("in") == "query"
            }
            # The mock advertises the previous run's output through
            # `documented_openapi`, so a second consecutive run saw its own
            # filters as already taken and wrote an empty table. What this
            # generator produced is not evidence that the route takes it.
            taken = {
                p["name"] for p in mocked_op.get("parameters", []) if p.get("in") == "query"
            } - {s.param for s in DOCUMENTED_FILTERS.get(path[len(PREFIX):], ())}
            missing = sorted(set(documented) - taken - NOT_FILTERS)
            if not missing:
                continue
            # More than one record, because a field only some records carry
            # reads as absent in the first one: sampling a single agent left
            # `lastSuccessfulScanDate` looking like anything but a timestamp,
            # and its filters kept comparing dates as text.
            response = client.get(f"{path}?limit=100", headers=headers)
            if response.status_code != 200:
                continue
            records = _records(response.json())
            sample = records[0] if records else None
            if sample is None:
                continue
            paths = _field_paths(sample)

            for name in missing:
                base, op = _operator(name)
                candidates = [base, base[:-1] if base.endswith("s") else f"{base}s"]
                field = next((paths[c] for c in candidates if c in paths), None)
                if field is None:
                    skipped += 1
                    continue
                declared = documented[name]
                enum = bool((declared.get("items") or {}).get("enum") or declared.get("enum"))
                if not op:
                    op = "in" if declared.get("type") == "array" else "eq"
                    if declared.get("type") == "boolean":
                        op = "bool"
                # The declared scalar type travels with the spec so the
                # filter layer can refuse a value it cannot hold. Only the
                # two the mock can check are carried; `array` is
                # `collectionFormat: csv` throughout and arrives as text.
                declared_type = declared.get("type")
                if declared_type in ("integer", "boolean"):
                    kind = declared_type
                elif _is_dated(declared, records, field, op):
                    kind = "date-time"
                else:
                    kind = "string"
                derived.setdefault(path[len(PREFIX):], []).append(
                    (name, field, op, enum, kind),
                )

    lines = [
        '"""Filters the SentinelOne swagger declares, generated — do not edit by hand.',
        "",
        "    backend/.venv/bin/python scripts/gen_documented_filters.py",
        "",
        "Each entry is a parameter the vendor documents whose field this mock's own",
        "response carries. The suffix decides the operator, `kind` carries the scalar",
        "type the swagger declares; a parameter whose field we do not have is",
        "not here and stays in `scripts/param_drift.py`'s count.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from utils.filtering import FilterSpec",
        "",
        "#: route (without the API prefix) -> the specs derived for it",
        "DOCUMENTED_FILTERS: dict[str, list[FilterSpec]] = {",
    ]
    for route, specs in sorted(derived.items()):
        lines.append(f'    "{route}": [')
        for name, field, op, enum, kind in sorted(specs):
            enum_arg = ", enum=True" if enum else ""
            kind_arg = f', kind="{kind}"' if kind != "string" else ""
            one_line = f'        FilterSpec("{name}", "{field}", "{op}"{enum_arg}{kind_arg}),'
            if len(one_line) <= LINE_LIMIT:
                lines.append(one_line)
            else:
                # ruff lints the generated file like any other, so the
                # generator wraps rather than leaving a line for a human to
                # fix by hand in a file whose header forbids that.
                lines.append("        FilterSpec(")
                packed = f'            "{name}", "{field}", "{op}"{enum_arg}{kind_arg},'
                if len(packed) <= LINE_LIMIT:
                    lines.append(packed)
                else:
                    lines.append(f'            "{name}",')
                    lines.append(f'            "{field}",')
                    lines.append(f'            "{op}",')
                    # Each extra argument already carries its leading ", ".
                    lines += [
                        f"            {arg.lstrip(', ')}," for arg in (enum_arg, kind_arg) if arg
                    ]
                lines.append("        ),")
        lines.append("    ],")
    lines.append("}")
    lines.append("")
    OUT.write_text("\n".join(lines))

    total = sum(len(v) for v in derived.values())
    print(f"{total} filters over {len(derived)} routes → {OUT.relative_to(ROOT)}")
    print(f"{skipped} documented parameters have no field in this mock's records")
    for route, specs in sorted(derived.items(), key=lambda kv: -len(kv[1]))[:10]:
        print(f"  {route:34} {len(specs):3}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
