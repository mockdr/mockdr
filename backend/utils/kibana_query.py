"""How Kibana refuses a query member the route does not declare.

8.15 does not ignore an unknown query member: it refuses the request with
400 before the handler runs, and its three validators word that refusal
three different ways (measured, `/api/status`, `/api/cases/tags` and
`/api/timeline`, each with `?zzz=1&qqq=2`):

    config-schema  [request query.zzz]: definition for this key is missing
    io-ts          invalid keys "zzz,qqq"
    excess         [request query]: Invalid value {"zzz":"1","qqq":"2"},
                   excess properties: ["zzz","qqq"]

The first names only the first unknown member, in the order the client sent
them; the other two name all of them. io-ts comes in two spellings of
the same message: the Cases API leaves the `[request query]: ` prefix off
and the exception-list API keeps it — four routes each, measured one by
one. mockdr answered 200 and ignored the
member, so a client that misspelled a filter saw an unfiltered result
reported as a successful, filtered one — and the same request 400s against
the product.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from fastapi.params import Depends as DependsMarker

from utils.es_response import build_kbn_error_response

#: `@kbn/config-schema` routes: the first unknown member, named.
KEY_MISSING = "key_missing"
#: io-ts routes (the Cases API): every unknown member, comma-joined.
INVALID_KEYS = "invalid_keys"
#: The same, as the exception-list API words it — with the prefix Cases drops.
PREFIXED_INVALID_KEYS = "prefixed_invalid_keys"
#: The runtime-type routes (Timeline): the query echoed, then the excess.
EXCESS = "excess"


def _message(dialect: str, sent: dict[str, str], extra: list[str]) -> str:
    """Word the refusal the way `dialect`'s validator words it."""
    if dialect in (INVALID_KEYS, PREFIXED_INVALID_KEYS):
        prefix = "[request query]: " if dialect == PREFIXED_INVALID_KEYS else ""
        return prefix + 'invalid keys "' + ",".join(extra) + '"'
    if dialect == EXCESS:
        return (
            "[request query]: Invalid value "
            + json.dumps(sent, separators=(",", ":"))
            + ", excess properties: "
            + json.dumps(extra, separators=(",", ":"))
        )
    return f"[request query.{extra[0]}]: definition for this key is missing"


def known_query_members(
    *known: str, dialect: str = KEY_MISSING, numbers: tuple[str, ...] = (),
) -> Callable[..., None]:
    """Refuse any query member outside `known` the way 8.15 refuses it.

    The route's own declared members are allowed too, so a member mockdr
    reads can never be refused by the very route that reads it.
    """
    measured = frozenset(known)

    def refuse(request: Request) -> None:
        route = request.scope.get("route")
        declared = {
            p.alias or p.name
            for p in getattr(getattr(route, "dependant", None), "query_params", ())
        }
        # dict, not set: the wordings name the members in the order sent.
        sent = dict(request.query_params)
        # A member config-schema declares as a number, given something that is
        # not one — an empty value included — is refused in its own words
        # before anything reads it.  `?page=` is `expected value of type
        # [number] but got [string]`, where an absent one is simply absent.
        for name in numbers:
            value = sent.get(name)
            if value is None:
                continue
            try:
                float(value)
            except ValueError:
                raise HTTPException(status_code=400, detail=build_kbn_error_response(
                    400,
                    f"[request query.{name}]: expected value of type [number] "
                    f"but got [string]",
                )) from None

        extra = [k for k in sent if k not in measured and k not in declared]
        if extra:
            # Refused before the handler is dispatched to, which is what
            # decides whether the answer carries `elastic-api-version`: 8.15
            # adds that header when it dispatches, so a query-schema refusal
            # on a versioned route carries none.  Measured on four routes.
            request.scope["kbn_refused_before_dispatch"] = True
            raise HTTPException(status_code=400, detail=build_kbn_error_response(
                400, _message(dialect, sent, extra),
            ))

    return refuse


def refuses_unknown(
    *known: str, dialect: str = KEY_MISSING, numbers: tuple[str, ...] = (),
) -> DependsMarker:
    """`known_query_members` as a route dependency."""
    marker: DependsMarker = Depends(
        known_query_members(*known, dialect=dialect, numbers=numbers))
    return marker
