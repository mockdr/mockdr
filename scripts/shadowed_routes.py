# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Find a route that a route registered before it already answers.

Starlette matches in registration order and stops at the first hit, so a
literal path declared *after* a sibling pattern that covers it never runs.
The route is in the app, it is in the OpenAPI document, `unreachable_code.py`
sees its handler as reached — and a client still gets the other handler's
answer, which for a by-id lookup is a 404 for a path that exists.

That is what this found: `GET /_dev/webhooks/deliveries` was declared in
`dev.py`, which is included after `webhooks.py`, so `/_dev/webhooks/{id}`
matched first and the delivery log was answered by a search for a
subscription called "deliveries". Not a 500, not a blank list — a 404 for a
route the mock publishes.

The check substitutes a placeholder for each of a route's own parameters and
asks whether any earlier route sharing a method matches the result. A route
whose siblings all have parameters in the same position is not flagged: two
patterns that overlap only where both take a parameter are the same route
declared twice, which the framework itself rejects.

    backend/.venv/bin/python scripts/shadowed_routes.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from fastapi.routing import _IncludedRouter  # noqa: E402
from main import app  # noqa: E402

_PARAM = re.compile(r"\{[^}]+\}")


def flatten(routes, prefix=""):
    """Every endpoint in the tree, in the order the router tries them."""
    for route in routes:
        if isinstance(route, _IncludedRouter):
            context = route.include_context
            yield from flatten(
                route.original_router.routes,
                prefix + (getattr(context, "prefix", "") or ""),
            )
            continue
        path = prefix + (getattr(route, "path", "") or "")
        mounted = getattr(getattr(route, "app", None), "routes", None)
        if mounted is not None and not hasattr(route, "methods"):
            yield from flatten(mounted, path)
        elif hasattr(route, "path_regex"):
            yield path, set(getattr(route, "methods", []) or [])


def shadowed(endpoints):
    """Each (path, methods) an earlier registration already answers."""
    flags, seen = [], []
    for path, methods in endpoints:
        # A request for this route's own literal shape: its parameters get a
        # placeholder, so what is left is what a client would actually send.
        sample = _PARAM.sub("sample", path)
        for earlier, earlier_methods in seen:
            if earlier == path or not methods & earlier_methods:
                continue
            if re.fullmatch(_PARAM.sub("[^/]+", earlier), sample):
                flags.append((path, methods, earlier, earlier_methods))
                break
        seen.append((path, methods))
    return flags


def main():
    """Report every route an earlier one already answers."""
    endpoints = list(flatten(app.routes))
    flags = shadowed(endpoints)

    print(f"=== SHADOWED ROUTES === {len(endpoints)} route(s) read, in match order")
    for path, methods, earlier, earlier_methods in flags:
        print(f"  {sorted(methods)} {path}")
        print(f"      answered by {sorted(earlier_methods)} {earlier}")
    print(f"\n  {len(flags)} route(s) nothing can reach")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
