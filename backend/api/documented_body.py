"""Refuse a SentinelOne write body that carries nothing the route knows.

Twenty-five write routes answered 200 to `{}` — a threat marked as an
incident with no verdict in the body, an exclusion created out of nothing, a
policy replaced by an empty document. Each reported success, which is the
worst answer a mock can give: the client goes on believing the write
happened the way it asked.

The vendor's own swagger says what those bodies are made of. Every one of
these routes declares `data`, `filter` or both as required, and declares the
members each holds. A body carrying none of those names is not a body for
this route, whichever of the accepted spellings the client meant — the
wrapped form or the flat one this mock also takes.

What this deliberately does *not* do is decide which combination is enough.
The swagger says `data` is required for `/threats/analyst-verdict`; whether
real S1 accepts the flat `{"analystVerdict": …}` is not something the
reference states and not something this repo can measure, so a body carrying
either is let through. The check is only that something was sent.
"""
from __future__ import annotations

import json

from fastapi import HTTPException, Request

from application.documented_bodies import DOCUMENTED_BODIES
from utils.vendor_errors import build_vendor_error

_WRITE_METHODS = frozenset({"POST", "PUT"})

#: SentinelOne wraps almost every write body in one of these two, and this
#: mock also takes the flat form of the same document. A body carrying either
#: has sent something whatever the route's own schema lists.
_WRAPPERS = frozenset({"data", "filter"})

#: Spellings this mock accepts that the swagger does not list. They are
#: leniencies with tests behind them, and the point of this check is to
#: refuse a body that says *nothing* — not to withdraw what the mock already
#: answers to.
_ALSO_ACCEPTED: dict[tuple[str, str], frozenset[str]] = {
    ("PUT", "/groups/{group_id}/move-agents"): frozenset({"agentIds"}),
}


async def require_documented_body(request: Request) -> None:
    """Refuse a write body with no member the swagger documents for the route.

    Raises:
        HTTPException: 400 in SentinelOne's envelope, naming what was missing.
    """
    if request.method not in _WRITE_METHODS:
        return
    route = request.scope.get("route")
    key = (request.method, getattr(route, "path", ""))
    documented = DOCUMENTED_BODIES.get(key)
    if not documented or not _takes_a_body(route):
        return
    documented = documented | _WRAPPERS | _ALSO_ACCEPTED.get(key, frozenset())

    raw = await request.body()
    if not raw:
        _refuse(documented)
    try:
        body = json.loads(raw)
    except ValueError:
        return  # Malformed JSON is the handler's own 400 to report.
    if not isinstance(body, dict) or not documented & set(body):
        _refuse(documented)


def _takes_a_body(route: object) -> bool:
    """Whether this route asks for a body at all.

    The swagger marks `data` required on routes that take no document here —
    reactivating a site, for one. Requiring a body of a handler that declares
    none would be inventing a rule rather than enforcing a documented one.
    """
    dependant = getattr(route, "dependant", None)
    return bool(getattr(dependant, "body_params", None))


def _refuse(documented: frozenset[str]) -> None:
    """Report the members this route would have recognised."""
    wanted = ", ".join(sorted(documented)[:8])
    raise HTTPException(
        status_code=400,
        detail=build_vendor_error(
            "sentinelone", 400,
            f"Request body carries none of the members this endpoint takes: {wanted}",
        ),
    )
