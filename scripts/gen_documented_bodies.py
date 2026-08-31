"""Derive what each vendor's reference says a write body must carry.

`body_audit.py` found routes that answered 200 to an empty body — twenty-five
on SentinelOne, six more on CrowdStrike. Each vendor's own reference says
what those bodies are made of, and a route taking one that carries none of it
is taking a body the vendor says is not one.

Two sources, because the two references are shaped differently:

* the SentinelOne 2.1 swagger (`data/swagger_2_1.json`), which marks `data`
  and `filter` required and declares the members each holds. This mock also
  accepts the flat form of those payloads, so `data`'s own members count as
  having been sent — which is why SentinelOne's rule is the loose one: the
  body must carry *something the route knows*, not a particular combination.
* `crowdstrike_gofalcon_reduced.json`, whose `request_required` names the
  members of a flat body with no wrapper to be ambiguous about.
* `xdr_openapi_reduced.json` for Cortex, where `request_data` is the wrapper
  and most routes require nothing at all — only the ones that state a
  requirement are carried over.

Written to:

    backend/application/documented_bodies.py

Nothing is guessed. A route the reference documents no body for is left out,
and so is one whose body declares nothing required.

    backend/.venv/bin/python scripts/gen_documented_bodies.py
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "data" / "swagger_2_1.json"
GOFALCON = ROOT / "data" / "vendor-specs" / "crowdstrike_gofalcon_reduced.json"
CORTEX = ROOT / "data" / "vendor-specs" / "xdr_openapi_reduced.json"
CORTEX_PREFIX = "/public_api/v1"
OUT = ROOT / "backend" / "application" / "documented_bodies.py"
S1_PREFIX = "/web/api/v2.1"

_MAX_DEPTH = 8

#: One row: vendor, method, the path the router carries, what the body must
#: carry, what makes it recognisable as a body for this route, and the
#: members the reference marks required *inside* `data`.
Row = tuple[str, str, str, list[str], list[str], list[str]]


def resolve(schema: dict, definitions: dict, depth: int = 0) -> dict:
    """Follow a `$ref` to the definition it names."""
    if depth > _MAX_DEPTH or not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if ref:
        return resolve(definitions.get(ref.split("/")[-1], {}), definitions, depth + 1)
    return schema


def member_names(schema: dict, definitions: dict) -> set[str]:
    """The members that make a SentinelOne body recognisable as one.

    The top-level ones, plus the members of the `data` payload — the flat
    form of the same document, which the mock takes as well.
    """
    resolved = resolve(schema, definitions)
    properties = resolved.get("properties") or {}
    names = set(properties)
    payload = resolve(properties.get("data", {}), definitions)
    # `data` is a list on the routes that create several records at once —
    # the flat form of those is one of its items, not the list.
    if payload.get("type") == "array":
        payload = resolve(payload.get("items", {}), definitions)
    names |= set(payload.get("properties") or {})
    return names


def payload_required(schema: dict, definitions: dict) -> list[str]:
    """What the swagger marks required inside a SentinelOne `data` payload.

    The top-level `required` is `["data", "filter"]` on almost every action,
    which says nothing about what the payload holds — and the payload's own
    `required` says exactly that: `analystVerdict` on the verdict route,
    `incidentStatus` on the incident route, `email` and `fullName` on
    `POST /users`. Fifty-one such members were documented and unenforced, so
    a verdict with no verdict in it answered `affected: 1` and changed
    nothing.
    """
    resolved = resolve(schema, definitions)
    payload = resolve((resolved.get("properties") or {}).get("data", {}), definitions)
    if payload.get("type") == "array":
        payload = resolve(payload.get("items", {}), definitions)
    return sorted(payload.get("required") or [])


def sentinelone_rows() -> list[Row]:
    """What the 2.1 swagger says each SentinelOne write body must carry."""
    if not SWAGGER.exists():
        print(f"missing {SWAGGER} — run scripts/fetch_swagger.sh first")
        return []
    swagger = json.loads(SWAGGER.read_text())
    definitions = swagger.get("definitions", {})

    rows: list[Row] = []
    for path, operations in sorted(swagger.get("paths", {}).items()):
        if not path.startswith(S1_PREFIX):
            continue
        for verb in ("post", "put"):
            operation = operations.get(verb)
            if not operation:
                continue
            bodies = [
                p for p in operation.get("parameters", []) if p.get("in") == "body"
            ]
            if not bodies:
                continue
            schema = bodies[0].get("schema", {})
            required = sorted(resolve(schema, definitions).get("required", []) or [])
            if not required:
                continue
            # Keyed without the API prefix, the way the router sees it —
            # `documented_filters.py` keys the same way.
            rows.append(("sentinelone", verb.upper(), path[len(S1_PREFIX):] or "/",
                         required, sorted(member_names(schema, definitions)),
                         payload_required(schema, definitions)))
    return rows


def crowdstrike_rows() -> list[Row]:
    """What gofalcon says each Falcon write body must carry."""
    if not GOFALCON.exists():
        print(f"missing {GOFALCON} — run scripts/gofalcon_spec.py first")
        return []
    reduced = json.loads(GOFALCON.read_text())

    rows: list[Row] = []
    for key, entry in sorted(reduced.items()):
        method, _, path = key.partition(" ")
        if method not in ("POST", "PUT", "PATCH"):
            continue
        required = sorted(entry.get("request_required") or [])
        if not required:
            continue
        # The top-level names only: a required `ids` is satisfied by `ids`,
        # not by anything inside it.
        members = sorted({
            name.split(".")[0].split("[")[0]
            for name in entry.get("request_paths") or []
        })
        # gofalcon's bodies are flat: there is no `data` payload to look
        # inside, so nothing is recorded for one.
        rows.append(("crowdstrike", method, path, required,
                     members or required, []))
    return rows


def cortex_rows() -> list[Row]:
    """What the Cortex reference says each XDR write body must carry.

    Most of its routes require nothing — `xql/get_quota` gives
    `{"request_data": null}` as its own example — so only the ones that state
    a requirement are here. The rest keep answering an empty body, because
    nothing says they should not.
    """
    if not CORTEX.exists():
        print(f"missing {CORTEX} — run scripts/cortex_openapi_spec.py first")
        return []
    reduced = json.loads(CORTEX.read_text())

    rows: list[Row] = []
    for key, entry in sorted(reduced.items()):
        method, _, path = key.partition(" ")
        required = sorted(entry.get("request_required") or [])
        if method not in ("POST", "PUT", "PATCH") or not required:
            continue
        members = sorted({
            name.split(".")[0].split("[")[0]
            for name in entry.get("request_paths") or []
        })
        # Keyed the way the router carries it: the mount takes the
        # `/public_api/v1` the reference spells out, and the mock's own paths
        # end in the slash the transcription omits.
        rows.append(("xdr", method, path[len(CORTEX_PREFIX):] + "/",
                     required, members or required, []))
    return rows


def render(rows: list[Row]) -> str:
    """The generated module."""
    lines = [
        '"""What each write body must carry, from each vendor\'s own reference.',
        "",
        "Generated by scripts/gen_documented_bodies.py — do not edit by hand.",
        "",
        "A route that answers 200 to a body carrying none of this is accepting",
        "a body the vendor's own reference says is not one.",
        "",
        "`required` is what the reference marks required. `recognisable` is",
        "every member that shows the client meant this route at all — for",
        "SentinelOne that includes the members of the `data` payload, because",
        "this mock takes the flat form of those documents as well.",
        "",
        "`payload_required` is what the swagger marks required *inside*",
        "`data`. The top-level `required` is `data, filter` on almost every",
        "SentinelOne action and says nothing about what the payload holds;",
        "the payload's own `required` says exactly that.",
        '"""',
        "from __future__ import annotations",
        "",
        "#: ``(vendor, method, route path)`` →",
        "#: ``(required, recognisable, payload_required)``.",
        "#: The path is the one the router carries — no mount prefix.",
        "DOCUMENTED_BODIES: dict[",
        "    tuple[str, str, str],",
        "    tuple[frozenset[str], frozenset[str], frozenset[str]],",
        "] = {",
    ]
    for vendor, method, path, required, members, payload in rows:
        key = f'    ("{vendor}", "{method}", "{path}"): ('
        if len(key) > 100:
            lines.append("    (")
            lines.append(f'        "{vendor}", "{method}",')
            lines.append(f'        "{path}",')
            lines.append("    ): (")
        else:
            lines.append(key)
        for values in (required, members, payload):
            joined = ", ".join(f'"{v}"' for v in values)
            lines.append("        frozenset({")
            lines += textwrap.wrap(joined, width=70, initial_indent=" " * 12,
                                   subsequent_indent=" " * 12)
            lines.append("        }),")
        lines.append("    ),")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    """Write the documented body members for every vendor with a reference."""
    rows = sentinelone_rows() + crowdstrike_rows() + cortex_rows()
    if not rows:
        return 2
    OUT.write_text(render(rows))
    counts = {
        vendor: sum(1 for row in rows if row[0] == vendor)
        for vendor in sorted({row[0] for row in rows})
    }
    print(f"{len(rows)} route(s) → {OUT.relative_to(ROOT)}  {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
