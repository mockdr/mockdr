# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Say which routes nothing is watching.

Every audit here reports what it found. None of them reports what it never
looked at, and that turned out to be where the defects were: `schema_drift.py`
printed "0 drift findings" over nineteen CrowdStrike routes while fourteen
more sat behind a "skipped" line, and the three Deep Visibility routes had
never once been compared. Both were invisible because the summary counted
findings rather than coverage.

This counts coverage. For every route the app serves it asks three questions:

* does a **schema comparison** judge its answer against a vendor reference?
* does a **conformance probe** compare it against the real product?
* does any **test** name it?

A route that nothing answers yes for is not necessarily wrong — it is
unwatched, which is a different thing and worth knowing by name.

    backend/.venv/bin/python scripts/audit_coverage.py [--all]

Exit status is always 0: this reports a map, it does not judge.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "scripts"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")

_PARAM = re.compile(r"\{[^}]+\}")


def shape(path: str) -> str:
    """The path with its parameters anonymised and its trailing slash gone.

    A reference records `/xql/get_quota` where the mount serves
    `/xql/get_quota/`, and either spelling must count as the same route.
    """
    return _PARAM.sub("{}", path).rstrip("/") or "/"


def served():
    """Every route the app serves, as (method, path)."""
    from fastapi.routing import _IncludedRouter  # noqa: PLC0415
    from main import app  # noqa: PLC0415

    def walk(routes, prefix=""):
        for route in routes:
            if isinstance(route, _IncludedRouter):
                context = route.include_context
                yield from walk(
                    route.original_router.routes,
                    prefix + (getattr(context, "prefix", "") or ""),
                )
                continue
            path = prefix + (getattr(route, "path", "") or "")
            mounted = getattr(getattr(route, "app", None), "routes", None)
            if mounted is not None and not hasattr(route, "methods"):
                yield from walk(mounted, path)
            elif hasattr(route, "path_regex"):
                for method in getattr(route, "methods", None) or ():
                    if method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                        yield method, path

    return sorted(set(walk(app.routes)))


def described():
    """Every route a vendor reference describes, as `METHOD /mounted/path`."""
    import schema_drift as drift  # noqa: PLC0415

    out: set[str] = set()
    for name, cfg in drift.PLATFORMS.items():
        mount = cfg.get("mount", "")
        sources = [cfg[k] for k in ("reduced",) if k in cfg] + list(cfg.get("reduced_extra", []))
        for source in sources:
            if not Path(source).exists():
                continue
            document = json.loads(Path(source).read_text())
            for key in _route_keys(document):
                method, path = key.split(" ", 1)
                out.add(f"{method.upper()} {shape(mount + path)}")
        if name == "sentinelone":
            swagger = ROOT / "data" / "swagger_2_1.json"
            if swagger.exists():
                for path, operations in json.loads(swagger.read_text())["paths"].items():
                    for method in operations:
                        if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                            out.add(f"{method.upper()} {shape(path)}")
        if name == "sentinel":
            for spec in sorted((ROOT / "data" / "vendor-specs").glob("sentinel_2024-03-01_*.json")):
                document = json.loads(spec.read_text())
                for path, operations in (document.get("paths") or {}).items():
                    for method in operations:
                        if method.upper() in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                            out.add(f"{method.upper()} {shape(mount + path)}")
    return out


def _route_keys(node, found=None):
    """Every `METHOD /path` key anywhere in a reduced reference."""
    found = set() if found is None else found
    if isinstance(node, dict):
        for key, value in node.items():
            if re.match(r"^(GET|POST|PUT|PATCH|DELETE) /", str(key)):
                found.add(str(key))
            _route_keys(value, found)
    elif isinstance(node, list):
        for item in node:
            _route_keys(item, found)
    return found


def probed():
    """Every path a conformance probe sends, by mount."""
    out: set[str] = set()
    mounts = {"search": "/elastic", "kibana": "/kibana", "management": "/splunk",
              "collector": "/splunk", "hec": "/splunk"}
    for probe in sorted((ROOT / "conformance" / "probes").glob("*.yaml")):
        endpoint = ""
        for line in probe.read_text().splitlines():
            named = re.match(r"\s*endpoint:\s*(\S+)", line)
            if named:
                endpoint = named.group(1)
            # A probe may be written in flow style — `request: {method: GET,
            # path: /api/cases/status, auth: basic}` — so `path:` is not at
            # the start of its line and nine probes written that way counted
            # as no coverage at all.
            path = re.search(r"\bpath:\s*([^\s,]+)", line)
            if path:
                mount = mounts.get(endpoint, "")
                # Flow style ends the value with the mapping's own brace —
                # `path: /api/cases/status, auth: basic}` — while a
                # placeholder carries balanced ones. Strip only what is not
                # closing a `${`.
                raw = path.group(1).strip('"\'')
                while raw.endswith("}") and raw.count("{") < raw.count("}"):
                    raw = raw[:-1]
                cleaned = re.sub(r"\$\{[^}]+\}", "{}", raw)
                out.add(shape(mount + cleaned.split("?")[0]))
    return out


def tested():
    """Every path literal any test names.

    A test writes its path as an f-string over a prefix constant —
    `f"{BASE}/threats/mark-as-threat"` — so the literal does not start with
    a slash and the tail after the first one is what names the route.
    """
    out: set[str] = set()
    for path in (ROOT / "backend" / "tests").rglob("*.py"):
        for hit in re.findall(r'["\']([^"\']*/[a-zA-Z0-9_\-./{}:]+)["\']', path.read_text()):
            tail = hit[hit.index("/"):]
            if len(tail) > 1:
                out.add(shape(re.sub(r"\{[^}]*\}", "{}", tail)))
    return out


#: How many segments of a literal must line up with a route's tail before it
#: counts as naming it. Two keeps `/query` from claiming every route that
#: ends in one.
_ENOUGH = 2


def names(literal: str, route: str) -> bool:
    """Whether a path literal names a route.

    A test builds its path from a prefix constant, so the literal it carries
    is the *tail* of the served route — and it carries a concrete id where
    the route has a parameter. The two are lined up from the right, with a
    parameter matching anything.
    """
    theirs = [s for s in literal.split("/") if s]
    ours = [s for s in route.split("/") if s]
    if not theirs or len(theirs) > len(ours):
        return False
    # A one-segment route (`/metrics`) can only be named in full.
    if len(theirs) < _ENOUGH and len(ours) > len(theirs):
        return False
    for mine, yours in zip(reversed(ours), reversed(theirs), strict=False):
        if mine != "{}" and yours != "{}" and mine != yours:
            return False
    return True


def main():
    """Report every served route and what, if anything, watches it."""
    show_all = "--all" in sys.argv
    routes = served()
    references, probes, tests = described(), probed(), tested()

    #: The catch-all that answers every path no route claims. It is reached
    #: by name from nowhere, because naming it is the one thing it is not
    #: for; the tests that exercise it ask for paths that do not exist.
    catch_all = "/{}"
    unwatched = []
    tally = {"reference": 0, "probe": 0, "only a test": 0}
    for method, path in routes:
        anonymous = shape(path)
        # A test or a probe carries a *concrete* id where the route has a
        # parameter, and usually builds the path from a prefix constant — so
        # the route is matched as a pattern against the tail of each literal.
        by_reference = f"{method} {anonymous}" in references
        by_probe = any(names(p, anonymous) or p.startswith(anonymous) for p in probes)
        by_test = any(names(t, anonymous) for t in tests)
        if by_reference:
            tally["reference"] += 1
        if by_probe:
            tally["probe"] += 1
        if by_test and not (by_reference or by_probe) and anonymous != catch_all:
            tally["only a test"] += 1
        if show_all:
            marks = "".join(
                letter if seen else "·"
                for letter, seen in (("R", by_reference), ("P", by_probe), ("T", by_test))
            )
            print(f"  {marks}  {method:6} {path}")
        elif not (by_reference or by_probe or by_test) and anonymous != catch_all:
            unwatched.append((method, path))

    print(f"=== AUDIT COVERAGE === {len(routes)} route(s) served")
    if not show_all:
        for method, path in unwatched:
            print(f"  {method:6} {path}")
        print(
            f"\n  {tally['reference']} judged against a vendor reference"
            f"\n  {tally['probe']} compared against the real product"
            f"\n  {tally['only a test']} watched by nothing but this repo's own tests"
            f"\n  {len(unwatched)} watched by nothing at all",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
