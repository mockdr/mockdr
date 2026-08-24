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

    backend/.venv/bin/python scripts/param_drift.py            # summary
    backend/.venv/bin/python scripts/param_drift.py --verbose  # every name
    backend/.venv/bin/python scripts/param_drift.py --max-mock-only 20
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWAGGER = ROOT / "data" / "swagger_2_1.json"
PREFIX = "/web/api/v2.1"


def _query_names(operation: dict) -> set[str]:
    return {p["name"] for p in operation.get("parameters", []) if p.get("in") == "query"}


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
            if args.verbose and (ignored or mock_only):
                print(f"  {method.upper()} {path[len(PREFIX):]}")
                if ignored:
                    print(f"      ignored  : {', '.join(ignored)}")
                if mock_only:
                    print(f"      mock-only: {', '.join(mock_only)}")

    print(
        f"\n=== PARAMETER DRIFT === {routes} routes compared\n"
        f"  {ignored_total} documented parameter(s) this mock does not take\n"
        f"  {mock_only_total} parameter(s) this mock takes that the swagger does not declare"
    )
    if args.max_mock_only is not None and mock_only_total > args.max_mock_only:
        print(f"  FAIL: more than {args.max_mock_only} undocumented parameters")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
