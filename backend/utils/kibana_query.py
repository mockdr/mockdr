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
them; the other two name all of them. mockdr answered 200 and ignored the
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
#: The runtime-type routes (Timeline): the query echoed, then the excess.
EXCESS = "excess"


def _message(dialect: str, sent: dict[str, str], extra: list[str]) -> str:
    """Word the refusal the way `dialect`'s validator words it."""
    if dialect == INVALID_KEYS:
        return 'invalid keys "' + ",".join(extra) + '"'
    if dialect == EXCESS:
        return (
            "[request query]: Invalid value "
            + json.dumps(sent, separators=(",", ":"))
            + ", excess properties: "
            + json.dumps(extra, separators=(",", ":"))
        )
    return f"[request query.{extra[0]}]: definition for this key is missing"


def known_query_members(*known: str, dialect: str = KEY_MISSING) -> Callable[..., None]:
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
        extra = [k for k in sent if k not in measured and k not in declared]
        if extra:
            raise HTTPException(status_code=400, detail=build_kbn_error_response(
                400, _message(dialect, sent, extra),
            ))

    return refuse


def refuses_unknown(*known: str, dialect: str = KEY_MISSING) -> DependsMarker:
    """`known_query_members` as a route dependency."""
    marker: DependsMarker = Depends(known_query_members(*known, dialect=dialect))
    return marker
