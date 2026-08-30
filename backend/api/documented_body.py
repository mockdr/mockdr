"""Refuse a write body that carries nothing the route was documented to take.

Thirty-one write routes answered 200 to `{}` — a threat marked as an
incident with no verdict, an exclusion created out of nothing, a Falcon host
action addressed to no host at all. Each reported success, which is the worst
answer a mock can give: the client goes on believing the write happened the
way it asked.

Each vendor's own reference says what those bodies are made of — the
SentinelOne swagger, gofalcon's `request_required` for Falcon, the community
transcription of the Cortex reference for XDR — and the check is the same
for all of them: the body must name *something this route takes*.

It deliberately stops short of demanding a particular combination. The
swagger marks both `data` and `filter` required on a SentinelOne action
while this mock also accepts the flat form of the same document, and
gofalcon marks both `indicators` and `bulk_update` required on one Falcon
route where a client sends one or the other. Which combination the product
accepts is not something either reference states and not something this repo
can measure. What both references do state is which names belong to the
route at all, and a body carrying none of them was never a body for it.
"""
from __future__ import annotations

import json

from fastapi import HTTPException, Request

from application.documented_bodies import DOCUMENTED_BODIES
from utils.vendor_errors import build_vendor_error

_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})

#: SentinelOne wraps almost every write body in one of these two, and this
#: mock also takes the flat form of the same document. A body carrying either
#: has sent something whatever the route's own schema lists.
_WRAPPERS = frozenset({"data", "filter"})

#: Spellings this mock accepts that the reference does not list. They are
#: leniencies with tests behind them, and the point of this check is to
#: refuse a body that says *nothing* — not to withdraw what the mock already
#: answers to.
_ALSO_ACCEPTED: dict[tuple[str, str, str], frozenset[str]] = {
    ("sentinelone", "PUT", "/groups/{group_id}/move-agents"): frozenset({"agentIds"}),
    # The alerts routes read the ids and the status of their predecessor,
    # `/detects/entities/detects/v2`, as well as the v3 spelling.
    ("crowdstrike", "POST", "/alerts/entities/alerts/v2"): frozenset({"ids"}),
    ("crowdstrike", "PATCH", "/alerts/entities/alerts/v3"): frozenset({
        "ids", "status", "assigned_to_uuid", "comment", "show_in_ui",
    }),
}


async def require_documented_body(request: Request) -> None:
    """Refuse a write body with no member the reference documents for the route.

    Raises:
        HTTPException: 400 in the vendor's own envelope, naming what was missing.
    """
    if request.method not in _WRITE_METHODS:
        return
    route = request.scope.get("route")
    vendor = _vendor_of(request)
    key = (vendor, request.method, str(getattr(route, "path", "")))
    contract = DOCUMENTED_BODIES.get(key)
    if contract is None or not _takes_a_body(route):
        return
    required, recognisable = contract

    raw = await request.body()
    if not raw:
        # No body at all is not an unrecognised body. A route whose body the
        # reference marks required is enforced by its own model, which
        # answers before this runs; a route whose body is optional — the
        # swagger leaves `PUT /sites/{id}/reactivate` that way — must still
        # take a bodyless call, which is how every client has always made it.
        return
    body: object = {}
    try:
        body = json.loads(raw)
    except ValueError:
        return  # Malformed JSON is the handler's own 400 to report.
    sent = set(body) if isinstance(body, dict) else set()

    accepted = required | recognisable | _ALSO_ACCEPTED.get(key, frozenset())
    if vendor == "sentinelone":
        accepted |= _WRAPPERS
    if not accepted & sent:
        wanted = ", ".join(sorted(accepted)[:8])
        _refuse(
            vendor,
            f"Request body carries none of the members this endpoint takes: {wanted}",
        )


def _vendor_of(request: Request) -> str:
    """Which vendor's rules this request is answered under.

    The mount decides it, and so does the envelope the refusal comes back in
    — a client parsing Falcon's `errors[]` must not be handed S1's.
    """
    path = request.url.path
    if path.startswith("/cs/"):
        return "crowdstrike"
    if path.startswith("/xdr/"):
        return "xdr"
    return "sentinelone"


def _takes_a_body(route: object) -> bool:
    """Whether this route asks for a body at all.

    A reference can mark a member required on a route that takes no document
    here — reactivating a SentinelOne site, for one. Requiring a body of a
    handler that declares none would be inventing a rule rather than
    enforcing a documented one.
    """
    dependant = getattr(route, "dependant", None)
    return bool(getattr(dependant, "body_params", None))


def _refuse(vendor: str, message: str) -> None:
    """Report the refusal in the envelope this vendor answers errors in."""
    raise HTTPException(
        status_code=400, detail=build_vendor_error(vendor, 400, message),
    )
