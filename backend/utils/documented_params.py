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
                "schema": {"type": "string"},
                "description": f"Documented filter on {spec.field} ({spec.type}).",
            }
            for spec in specs
        ]
    }
