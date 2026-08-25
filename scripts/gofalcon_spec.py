# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR0912, PLR2004
"""Reduce CrowdStrike's API surface from gofalcon into a route → shape map.

CrowdStrike's swagger is not publicly downloadable (the public URL answers a
CloudFront 403), but ``github.com/CrowdStrike/gofalcon`` is generated from
it by go-swagger and versions every operation (``PathPattern``), every 200
response (``Payload *models.X``) and every model (a struct whose fields
carry ``json:"name"`` tags). This walks the three and writes
``data/vendor-specs/crowdstrike_gofalcon_reduced.json``:

    {"GET /devices/entities/devices/v2": {"id": "GetDeviceDetailsV2",
      "model": "DeviceapiDeviceDetailsResponseSwagger",
      "paths": ["errors", "errors[*].code", ..., "resources[*].agent_version"]}}

A write route also carries what it *accepts*, taken from the ``Body *models.X``
field of its ``*_parameters.go``, under ``request`` / ``request_paths`` — the
half of the contract no other comparator here holds. A mock that reads a
create body one level flatter than the vendor documents answers 200 and
stores nothing.

    git clone --depth 1 https://github.com/CrowdStrike/gofalcon /tmp/gofalcon
    backend/.venv/bin/python scripts/gofalcon_spec.py /tmp/gofalcon
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "crowdstrike_gofalcon_reduced.json"

_STRUCT = re.compile(r"^type (\w+) struct \{\n(.*?)^\}", re.M | re.S)
_FIELD = re.compile(r"^\s*(\w+)\s+([\w\[\]\*\.]+)\s+`json:\"([^\",]+)")
# Operation IDs may be dotted ("indicator.get.v1"); the response struct is
# named after the Reader ("IndicatorGetV1Reader" -> "IndicatorGetV1OK").
_OP = re.compile(
    r'ID:\s+"[\w.\-]+",\s*Method:\s+"(\w+)",\s*PathPattern:\s+"([^"]+)",.*?Reader:\s+&(\w+)Reader\{',
    re.S,
)
_PAYLOAD = re.compile(
    r"type (\w+)(?:OK|Created|Accepted) struct \{.*?Payload \*?models\.(\w+)", re.S
)
#: `Body *models.X` in a `<operation>_parameters.go`, whose file name is the
#: snake_case of the operation the `_client.go` names.
_BODY = re.compile(r"^\tBody \*?models\.(\w+)$", re.M)
#: `Required: true` sits in the doc comment directly above the field.
_REQUIRED = re.compile(r"// Required: true\n\s*\w+\s+[\w\[\]\*\.]+\s+`json:\"([^\",]+)")


def models(repo: Path) -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {}
    for f in (repo / "falcon" / "models").glob("*.go"):
        text = f.read_text(encoding="utf-8", errors="replace")
        for name, body in _STRUCT.findall(text):
            fields = []
            for line in body.splitlines():
                m = _FIELD.match(line)
                if m:
                    fields.append((m.group(3), m.group(2)))
            out[name] = fields
    return out


def _base(go_type: str) -> tuple[str, bool]:
    """Return ``("Name", is_array)`` for ``[]*Name``, ``*Name``, ``map[string]Name``.

    The gofalcon models spell an optional array of models as any of those.
    """
    is_array = go_type.startswith("[]")
    t = go_type.lstrip("[]*").replace("models.", "")
    if t.startswith("map["):
        t = t.split("]", 1)[1].lstrip("*")
    return t, is_array


def flatten(name: str, defs: dict, prefix: str = "", depth: int = 0, seen=()) -> list[str]:
    out: list[str] = []
    if depth > 6 or name in seen:
        return out
    for json_name, go_type in defs.get(name, []):
        path = prefix + json_name
        out.append(path)
        base, is_array = _base(go_type)
        if base in defs:
            sub = path + ("[*]." if is_array else ".")
            out.extend(flatten(base, defs, sub, depth + 1, (*seen, name)))
        elif is_array:
            out.append(path + "[*]")
    return out


def snake(name: str) -> str:
    """``QueryCombinedHostGroups`` and ``indicator.create.v1`` → file stem."""
    name = name.replace(".", "_").replace("-", "_")
    name = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name)
    return re.sub(r"(?<=[A-Z])([A-Z][a-z])", r"_\1", name).lower()


def required(repo: Path, model: str) -> list[str]:
    """The members a model marks ``Required: true``, in JSON spelling."""
    stem = snake(model).replace("_ap_i_", "_api_")
    for candidate in (stem, stem.replace("_v_", "_v")):
        f = repo / "falcon" / "models" / f"{candidate}.go"
        if f.exists():
            body = _STRUCT.search(f.read_text(encoding="utf-8", errors="replace"))
            return sorted(set(_REQUIRED.findall(body.group(2)))) if body else []
    return []


def main(repo: Path) -> int:
    defs = models(repo)
    payloads: dict[str, str] = {}
    bodies: dict[str, str] = {}
    ops: dict[str, tuple[str, str]] = {}
    for f in (repo / "falcon" / "client").rglob("*.go"):
        text = f.read_text(encoding="utf-8", errors="replace")
        if f.name.endswith("_responses.go"):
            for op, model in _PAYLOAD.findall(text):
                payloads[op] = model
        elif f.name.endswith("_parameters.go"):
            found = _BODY.search(text)
            if found:
                bodies[f.name[: -len("_parameters.go")]] = found.group(1)
        elif f.name.endswith("_client.go"):
            for method, path, op in _OP.findall(text):
                ops[op] = (method, path)
    reduced = {}
    for op, (method, path) in sorted(ops.items(), key=lambda kv: kv[1]):
        model = payloads.get(op)
        if not model:
            continue
        entry = {"id": op, "model": model, "paths": flatten(model, defs)}
        request = bodies.get(snake(op))
        if request:
            entry["request"] = request
            entry["request_paths"] = flatten(request, defs)
            entry["request_required"] = required(repo, request)
        reduced[f"{method} {path}"] = entry
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    print(
        f"models: {len(defs)}  operations: {len(ops)}  "
        f"with 200 payload: {len(reduced)}  with a request body: "
        f"{sum('request' in e for e in reduced.values())} → {OUT.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    # S108: the default is the clone path the module docstring documents, not a
    # file this script creates.
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/gofalcon")))  # noqa: S108
