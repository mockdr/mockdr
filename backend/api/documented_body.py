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

It deliberately stops short of demanding a particular combination *at the
top level*. The swagger marks both `data` and `filter` required on a
SentinelOne action while this mock also accepts the flat form of the same
document, and gofalcon marks both `indicators` and `bulk_update` required on
one Falcon route where a client sends one or the other. Which combination
the product accepts is not something either reference states.

Inside the `data` payload it does state it, and there the check is exact.
`POST /threats/analyst-verdict` requires `data.analystVerdict`; without it
the mock answered `{"affected": 1}` and left every verdict where it was.
Fifty-one such members were documented and unenforced across the SentinelOne
surface — a user created with no e-mail address, a note with no text, a
site with no name — each answering with an id, as though the record it
described had been made.
"""
from __future__ import annotations

import json

from fastapi import HTTPException, Request

from application.documented_bodies import DOCUMENTED_BODIES
from repository.user_repo import user_repo
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
    required, recognisable, payload_required = contract

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
    if _may_write(request, vendor):
        _require_payload_members(payload_required, body, vendor)


#: Which roles each permission dependency lets through, by its own name.
#: Read off the route rather than guessed at: `POST /users` wants an Admin
#: and `POST /threats/analyst-verdict` takes a SOC Analyst too, and a rule
#: that could not tell them apart refused one of them in the wrong words.
_PERMISSION_ROLES: dict[str, frozenset[str]] = {
    "require_admin": frozenset({"Admin"}),
    "require_write": frozenset({"Admin", "SOC Analyst"}),
}
_MAX_DEPENDANT_DEPTH = 8


def _permission_of(route: object, depth: int = 0) -> frozenset[str] | None:
    """The roles this route's own permission dependency admits, if it has one."""
    dependant = route if depth else getattr(route, "dependant", None)
    if dependant is None or depth > _MAX_DEPENDANT_DEPTH:
        return None
    name = getattr(getattr(dependant, "call", None), "__name__", "")
    roles = _PERMISSION_ROLES.get(name)
    if roles is not None:
        return roles
    for sub in getattr(dependant, "dependencies", ()):
        found = _permission_of(sub, depth + 1)
        if found is not None:
            return found
    return None


def _may_write(request: Request, vendor: str) -> bool:
    """Whether this caller passes the route's own permission check.

    A caller who does not must meet that route's 403 and must not be told,
    on the way there, which member its body was missing:
    `test_authorisation_is_decided_before_the_body` records that, and naming
    the member hands the shape of the API to someone with no right to it.

    The roles come off the route's own dependency rather than from a guess
    here, because they differ: `POST /users` admits an Admin alone and
    `POST /threats/analyst-verdict` admits a SOC Analyst as well.
    """
    if vendor != "sentinelone":
        return True
    roles = _permission_of(request.scope.get("route"))
    if roles is None:
        # No permission dependency to defer to.
        return True
    header = request.headers.get("authorization") or ""
    if not header.startswith("ApiToken "):
        # No usable credential: the 401 is the answer, not a body complaint.
        return False
    record = user_repo.get_token_record(header[len("ApiToken "):])
    if not isinstance(record, dict):
        return False
    return str(record.get("role") or "") in roles


def _require_payload_members(
    wanted: frozenset[str], body: object, vendor: str,
) -> None:
    """Refuse a `data` payload missing a member the reference marks required.

    The flat form counts: this mock takes `{"analystVerdict": …}` as well as
    `{"data": {"analystVerdict": …}}`, so a member found at either level has
    been sent. Naming only the first missing one is how the mock already
    words this, measured against its own `/exclusions` refusal:
    `data.osType is required`.
    """
    if not wanted or not isinstance(body, dict):
        return
    payload = body.get("data")
    if isinstance(payload, list):
        # The routes that create several records at once: each item is one
        # document, and each must be complete.
        items = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        items = [payload]
    elif payload is None:
        # The flat form — the document sent without its wrapper.
        items = [body]
    else:
        return
    for item in items:
        missing = sorted(name for name in wanted if item.get(name) in (None, ""))
        if missing:
            _refuse(vendor, f"data.{missing[0]} is required")


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
