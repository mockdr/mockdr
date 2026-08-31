"""Compare the query parameters a route declares with the ones the vendor does.

``field_drift.py`` compares response *fields*; a filter is invisible to it. A
documented parameter the mock does not declare is dropped by FastAPI and the
route answers 200 with the whole collection — the client asked a question and
got an answer to a different one. This reads the SentinelOne 2.1 swagger and
the mock's own OpenAPI and reports, per route:

    ignored   a parameter the vendor documents and this mock does not take
    mock-only a parameter this mock takes and the vendor does not document

Neither is automatically a defect: no mock implements 1 000 filters, and some
of the mock's own names predate the comparison. The number is the point — it
is stated, not discovered later by a client.

The same comparison one level up — a *route* the mock serves that the vendor
does not publish — was not counted anywhere, and that is how a wildcard
standing in for thirty-eight documented actions answered to any name at all.
It is listed here now. `_dev` is mockdr's own control surface and never
claimed to be SentinelOne's, so it is left out; path parameters are compared
by position, because the two sides name them differently.

    backend/.venv/bin/python scripts/param_drift.py            # summary
    backend/.venv/bin/python scripts/param_drift.py --verbose  # every name
    backend/.venv/bin/python scripts/param_drift.py --max-mock-only 20
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import warnings
from pathlib import Path

#: The routes this mock serves that the 2.1 swagger does not publish, each
#: with what the vendor documents instead. They are listed rather than
#: tolerated: anything *not* here fails, so the set cannot grow quietly
#: again — it had reached nine, printed on every run of a script nothing in
#: CI called.
#:
#: `POST /threats/mark-as-threat` and `POST /threats/mark-as-resolved` were
#: two of the nine and are gone: `/threats/analyst-verdict` and
#: `/threats/incident` do the same work and are published.
_KNOWN_UNPUBLISHED: dict[str, str] = {
    "DELETE /web/api/v2.1/exclusions/{}":
        "the vendor deletes by body: DELETE /exclusions",
    "PUT /web/api/v2.1/exclusions/{}":
        "the vendor updates by body: PUT /exclusions",
    "DELETE /web/api/v2.1/restrictions/{}":
        "the vendor deletes by body: DELETE /restrictions",
    "DELETE /web/api/v2.1/tag-manager/{}":
        "the vendor deletes by body: DELETE /tag-manager",
    "POST /web/api/v2.1/threat-intelligence/iocs/bulk":
        "the vendor creates several at once through POST /threat-intelligence/iocs",
    "POST /web/api/v2.1/threats/{}/notes":
        "the vendor adds notes in bulk: POST /threats/notes with a filter",
    "PUT /web/api/v2.1/firewall-control":
        "the vendor takes PUT on /firewall-control/{category}, not the bare path",
}

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "data" / "swagger_2_1.json"
PREFIX = "/web/api/v2.1"


def _query_names(operation: dict) -> set[str]:
    return {p["name"] for p in operation.get("parameters", []) if p.get("in") == "query"}


_METHODS = ("get", "post", "put", "delete", "patch")

#: One route standing in for many documented ones. It is not undocumented
#: surface: it refuses every name the vendor does not publish, with the 404 a
#: path that does not exist answers.
_STANDS_IN_FOR_MANY = frozenset({("POST", f"{PREFIX}/agents/actions/{{}}")})


def _shape(path: str) -> str:
    """The path with its parameters anonymised, so names cannot differ."""
    return re.sub(r"\{[^}]+\}", "{}", path)


def _scalar(schema: dict) -> str | None:
    """The scalar type a mock parameter's schema settles on, if it settles."""
    for key in ("anyOf", "oneOf"):
        if key in schema:
            kinds = {member.get("type") for member in schema[key]} - {"null"}
            return next(iter(kinds)) if len(kinds) == 1 else None
    kind = schema.get("type")
    return str(kind) if isinstance(kind, str) else None


def _type_drift(
    path: str, method: str, documented: dict, mocked: dict,
) -> list[str]:
    """Parameters both sides declare, where the mock's type is not the vendor's.

    Comparing names alone was not enough: `resolved` and `coreCount__lt` were
    on both lists and so counted as agreed, while the mock took them as text
    and read `resolved=maybe` as false — a 200 with every unresolved threat
    for a client whose value was nonsense. Only the type said so.

    `array` is excluded, and by measurement rather than assumption: every one
    of the 16 222 array parameters in this swagger is `collectionFormat: csv`,
    so it travels as one comma-separated string and a mock that takes a string
    is right.
    """
    vendor = {
        p["name"]: p.get("type")
        for p in documented.get("parameters", []) or []
        if p.get("in") == "query"
    }
    drift = []
    for parameter in mocked.get("parameters", []) or []:
        if parameter.get("in") != "query":
            continue
        want = vendor.get(parameter["name"])
        got = _scalar(parameter.get("schema", {}))
        if want and got and want != got and want != "array":
            drift.append(
                f"{method.upper()} {path[len(PREFIX):]} {parameter['name']}: "
                f"swagger {want}, mock {got}",
            )
    return drift


def _undocumented_routes(spec: dict, mock: dict) -> list[str]:
    """Every route the mock serves under the vendor's prefix that it does not."""
    documented = {
        (method.upper(), _shape(path))
        for path, operations in spec["paths"].items()
        for method in operations
        if method in _METHODS
    }
    served = {
        (method.upper(), _shape(path))
        for path, operations in mock["paths"].items()
        if path.startswith(PREFIX) and "/_dev/" not in path
        for method in operations
        if method in _METHODS
    }
    return [
        f"{method} {path}"
        for method, path in sorted(served - documented - _STANDS_IN_FOR_MANY)
    ]


def _unserved_methods(spec: dict, mock: dict) -> list[str]:
    """Every documented method on a path this mock serves with other verbs.

    The per-route comparison below skips these silently — it can only compare
    an operation both sides describe — and a 405 on a documented call is
    invisible to every audit that reads answers. Six were found this way:
    `PUT /exclusions`, which is how a real client updates one, and the
    update and delete-by-filter calls beside it.
    """
    return [
        f"{method.upper()} {path}"
        for path, operations in sorted(spec["paths"].items())
        if path in mock["paths"]
        for method in sorted(
            {m for m in operations if m in _METHODS}
            - {m for m in mock["paths"][path] if m in _METHODS}
        )
    ]


def main() -> int:
    """Report the parameter difference for every route both sides describe."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verbose", action="store_true", help="list every parameter name")
    parser.add_argument(
        "--max-mock-only",
        type=int,
        default=None,
        help="fail when more parameters exist that the vendor does not document",
    )
    args = parser.parse_args()

    if not SWAGGER.exists():
        print(f"{SWAGGER.relative_to(ROOT)} is missing — run scripts/fetch_swagger.sh")
        return 2

    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    sys.path.insert(0, str(ROOT / "backend"))
    from main import app  # noqa: PLC0415 - importing the app runs its startup

    spec = json.loads(SWAGGER.read_text())
    mock = app.openapi()

    routes = ignored_total = mock_only_total = 0
    mistyped: list[str] = []
    for path, operations in sorted(spec["paths"].items()):
        if path not in mock["paths"]:
            continue
        for method, operation in operations.items():
            mocked_operation = mock["paths"][path].get(method)
            if mocked_operation is None:
                continue
            routes += 1
            documented = _query_names(operation)
            mocked = _query_names(mocked_operation)
            ignored = sorted(documented - mocked)
            mock_only = sorted(mocked - documented)
            ignored_total += len(ignored)
            mock_only_total += len(mock_only)
            mistyped += _type_drift(path, method, operation, mocked_operation)
            if args.verbose and (ignored or mock_only):
                print(f"  {method.upper()} {path[len(PREFIX):]}")
                if ignored:
                    print(f"      ignored  : {', '.join(ignored)}")
                if mock_only:
                    print(f"      mock-only: {', '.join(mock_only)}")

    undocumented = _undocumented_routes(spec, mock)
    unserved = _unserved_methods(spec, mock)
    print(
        f"\n=== PARAMETER DRIFT === {routes} routes compared\n"
        f"  {ignored_total} documented parameter(s) this mock does not take\n"
        f"  {mock_only_total} parameter(s) this mock takes that the swagger does not declare\n"
        f"  {len(mistyped)} parameter(s) both sides declare, with different types\n"
        f"  {len(undocumented)} route(s) this mock serves that the swagger does not publish"
    )
    for entry in mistyped:
        print(f"      {entry}")
    for route in undocumented:
        print(f"      {route}")
    print(f"  {len(unserved)} documented method(s) answered 405 on a path this mock serves")
    for route in unserved:
        print(f"      {route}")
    if args.max_mock_only is not None and mock_only_total > args.max_mock_only:
        print(f"  FAIL: more than {args.max_mock_only} undocumented parameters")
        return 1

    # The parameter counts are reported, not judged: no mock implements a
    # thousand filters. A *route* the vendor does not publish is judged,
    # because "no evidence, no route" is a rule rather than a number — and
    # the ones already here are named above with what to use instead.
    new = [r for r in undocumented if r not in _KNOWN_UNPUBLISHED]
    if new:
        print(f"\n  FAIL: {len(new)} route(s) with no evidence in the swagger")
        for route in new:
            print(f"      {route}")
        return 1
    if _KNOWN_UNPUBLISHED:
        print(f"\n  {len(_KNOWN_UNPUBLISHED)} unpublished route(s) known and listed:")
        for route, instead in sorted(_KNOWN_UNPUBLISHED.items()):
            print(f"      {route}\n          {instead}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
