"""How a cluster refuses a query parameter it does not know.

Elasticsearch does not ignore an unrecognised parameter: it refuses the
request before running it, naming the parameter and the path it was sent to
(measured on 8.15):

    request [/conformance-seeded/_search] contains unrecognized parameter: [zzz]
    request [/_cluster/health] contains unrecognized parameters: [aaa], [zzz]

Several are named alphabetically, not in the order they were sent. mockdr
answered 200 and ignored them, so a client that wrote `siz` for `size` got a
full result set back where a real cluster would have refused the request
outright — the worst shape of wrongness there is, an answer that looks right
and is not.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request
from fastapi.params import Depends as DependsMarker

#: What every Elasticsearch route accepts, whatever else it takes.
COMMON = ("error_trace", "filter_path", "format", "human", "pretty")

#: mockdr's own mount, which the cluster the message describes does not have.
_MOUNT = "/elastic"


def _reason(path: str, extra: list[str]) -> str:
    """The cluster's wording for the parameters it did not recognise."""
    named = ", ".join(f"[{name}]" for name in sorted(extra))
    plural = "parameter" if len(extra) == 1 else "parameters"
    return f"request [{path}] contains unrecognized {plural}: {named}"


def known_params(*known: str, source: bool = True) -> Callable[..., None]:
    """Refuse any query parameter outside `known` the way a cluster does.

    `source` is the JSON-in-the-query-string escape hatch, which the search
    routes take and `/`, `_cat/*`, `_cluster/health` and
    `_security/_authenticate` do not — measured, one route at a time.

    `source_content_type` goes with it and is recognised only beside it: on
    its own the cluster calls it unrecognised, which is why asking after one
    parameter at a time could not see it.
    """
    allowed = frozenset(known) | frozenset(COMMON) | ({"source"} if source else set())

    def refuse(request: Request) -> None:
        sent = dict(request.query_params)
        conditional = {"source_content_type"} if source and "source" in sent else set()
        extra = [k for k in sent if k not in allowed and k not in conditional]
        if not extra:
            return
        path = request.url.path
        if path.startswith(_MOUNT):
            path = path[len(_MOUNT):] or "/"
        reason = _reason(path, extra)
        raise HTTPException(status_code=400, detail={
            "error": {
                "root_cause": [{"type": "illegal_argument_exception", "reason": reason}],
                "type": "illegal_argument_exception",
                "reason": reason,
            },
            "status": 400,
        })

    return refuse


def refuses_unknown(*known: str, source: bool = True) -> DependsMarker:
    """`known_params` as a route dependency."""
    marker: DependsMarker = Depends(known_params(*known, source=source))
    return marker
