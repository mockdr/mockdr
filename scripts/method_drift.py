# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Find a documented method this mock answers 405 to.

`param_drift.py` compares the parameters of operations both sides describe,
and `unreachable_code.py` and `shadowed_routes.py` read what the mock has.
None of them can see the gap between them: a method the vendor documents on
a path this mock already serves. The path is there, the OpenAPI document
lists it, the handlers beside it work — and the one call a client makes on
it is a 405.

Seven were found this way. Six on the SentinelOne surface, five of which are
how a real client writes: SentinelOne updates an exclusion and a blocklist
entry by body rather than by a path of its own (`PUT /exclusions`,
`PUT /restrictions`), and deletes rules and tags by filter
(`DELETE /cloud-detection/rules`, `DELETE /tag-manager`). The seventh was
`PATCH /api/machines/{id}`, the Defender call that changes a machine, on a
path serving six action routes and a GET.

Only paths both sides have are compared: a route the mock does not serve at
all is a 404, which is honest, and `param_drift.py` already lists the
routes it serves that the vendor does not publish.

    backend/.venv/bin/python scripts/method_drift.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_METHODS = ("get", "post", "put", "patch", "delete")
_PARAM = re.compile(r"\{[^}]+\}")

#: Each vendor reference, the prefix its routes are mounted under here, and
#: how a route is written in it. The SentinelOne swagger is an OpenAPI
#: document; the rest are reduced references whose keys read "GET /path".
_REFERENCES = (
    ("SentinelOne", "data/swagger_2_1.json", "", "openapi"),
    ("CrowdStrike", "data/vendor-specs/crowdstrike_gofalcon_reduced.json", "/crowdstrike", "keys"),
    ("Defender", "data/vendor-specs/mde_docs_reduced.json", "/mde", "keys"),
    ("Graph", "data/vendor-specs/graph_v1.0_reduced.json", "/graph", "keys"),
    ("Cortex XDR", "data/vendor-specs/xdr_openapi_reduced.json", "/xdr", "keys"),
    ("Cortex XDR", "data/vendor-specs/xdr_connector_reduced.json", "/xdr", "keys"),
)


def shape(path):
    """The path with its parameters anonymised, so names cannot differ."""
    return _PARAM.sub("{}", path)


def documented(spec, dialect):
    """Every (method, path) a reference describes."""
    if dialect == "openapi":
        return {
            (method, path)
            for path, operations in spec.get("paths", {}).items()
            for method in operations
            if method in _METHODS
        }
    found = set()
    route = re.compile(r"^(GET|POST|PUT|PATCH|DELETE) (/.*)$")

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                match = route.match(str(key))
                if match:
                    found.add((match.group(1).lower(), match.group(2)))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(spec)
    return found


def served(mock):
    """Every method this mock serves, by anonymised path."""
    by_path: dict[str, set[str]] = {}
    for path, operations in mock["paths"].items():
        by_path.setdefault(shape(path), set()).update(
            method for method in operations if method in _METHODS
        )
    return by_path


def main():
    """Report every documented method answered 405 on a path this mock serves."""
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from main import app  # noqa: PLC0415 - importing the app runs its startup

    mock = served(app.openapi())

    flags, compared = [], 0
    for vendor, relative, prefix, dialect in _REFERENCES:
        path = ROOT / relative
        if not path.exists():
            print(f"  {vendor}: {relative} is missing")
            continue
        for method, route in sorted(documented(json.loads(path.read_text()), dialect)):
            full = shape(prefix + route)
            if full not in mock:
                continue
            compared += 1
            if method not in mock[full]:
                flags.append((vendor, method.upper(), full))

    print(f"=== METHOD DRIFT === {compared} documented operation(s) on paths this mock serves")
    for vendor, method, path in flags:
        print(f"  {vendor:12} {method:6} {path}")
    print(f"\n  {len(flags)} documented method(s) answered 405")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
