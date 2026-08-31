"""Accept the query parameters the vendor documents, beyond the declared ones.

`application/documented_filters.py` derives one filter per documented
parameter whose field this mock's records carry — 343 of them. Declaring
each in a handler's signature would add hundreds of arguments to seventeen
functions; this reads them from the request instead, keeping only the names
that route has a filter for, so an unknown parameter is still ignored the
way FastAPI ignores it today.

The names are also reported in the route's OpenAPI (``openapi_extra``), so
`scripts/param_drift.py` and any client generating from the mock see them.
"""

from __future__ import annotations

from typing import Any

from starlette.requests import Request

from application.documented_filters import DOCUMENTED_FILTERS


def documented_params(request: Request, route: str) -> dict[str, str]:
    """The documented filter parameters this request carries for ``route``."""
    names = {spec.param for spec in DOCUMENTED_FILTERS.get(route, ())}
    if not names:
        return {}
    return {
        key: value
        for key, value in request.query_params.items()
        if key in names and value != ""
    }


def _schema_for(kind: str) -> dict[str, Any]:
    """The JSON Schema for a spec's declared kind.

    JSON Schema knows seven types and `date-time` is not one of them: it is a
    `format` over `string`.
    """
    if kind == "date-time":
        return {"type": "string", "format": "date-time"}
    return {"type": kind}


def documented_openapi(route: str) -> dict[str, Any]:
    """An ``openapi_extra`` block declaring the filters derived for ``route``."""
    specs = DOCUMENTED_FILTERS.get(route, ())
    if not specs:
        return {}
    return {
        "parameters": [
            {
                "name": spec.param,
                "in": "query",
                "required": False,
                # The type the swagger declares, not a blanket `string`:
                # this block *is* what the mock advertises for these
                # parameters, so declaring them all as text told every reader
                # the opposite of what the filter layer now enforces.
                #
                # `date-time` is a JSON Schema *format*, not a type — writing
                # it as a type made 85 parameters of this mock's own
                # `/openapi.json` invalid, which a client generating code
                # from it would choke on.
                "schema": _schema_for(spec.kind),
                "description": f"Documented filter on {spec.field} ({spec.type}).",
            }
            for spec in specs
        ]
    }
