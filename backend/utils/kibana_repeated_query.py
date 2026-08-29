"""What Kibana does when a query member is given twice.

8.15 refuses a repeat for a member it declares as a scalar, and accepts one
for a member it declares as an array: `status=open&status=closed` on the
Cases API is a 200, while `perPage=1&perPage=3` beside it is a 400.  mockdr
took the last value and answered 200 for both, so a client whose URL builder
appended a filter twice read a page from the mock and got a 400 from the
product.

The wording is the route's own validator's, in three dialects and two types:

    config-schema  [request query.page]: expected value of type [number]
                   but got [Array]
    io-ts          Invalid value "["1","2"]" supplied to "perPage"
                   — with the `[request query]: ` prefix on the
                   exception-list API and without it on the Cases API
    zod            [request query]: page: Expected number, received nan
                   (a string member reads `Expected string, received array`)

Which members are scalars cannot be read off mockdr's own signatures: they
are all `str` there on purpose, so that FastAPI's 422 never pre-empts
Kibana's wording.  So the table below is the measurement — every query
member mockdr declares, asked of 8.15 once and twice, 29 of 56 refusing.
"""
from __future__ import annotations

from fastapi import HTTPException, Request

from utils.es_response import build_kbn_error_response

CONFIG = "config-schema"
IOTS = "io-ts"
IOTS_PREFIXED = "io-ts-prefixed"
ZOD = "zod"

_REPEATED: dict[str, dict[str, tuple[str, str]]] = {
    "/api/actions/connector_types": {
        "feature_id": (CONFIG, "string"),
    },
    "/api/alerting/rules/_find": {
        "page": (CONFIG, "number"),
        "per_page": (CONFIG, "number"),
    },
    "/api/cases/_find": {
        "page": (IOTS, "any"),
        "perPage": (IOTS, "any"),
        "search": (IOTS, "any"),
    },
    "/api/detection_engine/rules": {
        "rule_id": (ZOD, "string"),
    },
    "/api/detection_engine/rules/_find": {
        "page": (ZOD, "number"),
        "per_page": (ZOD, "number"),
    },
    "/api/endpoint/metadata": {
        "page": (CONFIG, "number"),
        "pageSize": (CONFIG, "number"),
    },
    "/api/endpoint/policy_response": {
        "agentId": (CONFIG, "string"),
    },
    "/api/exception_lists": {
        "id": (IOTS_PREFIXED, "any"),
        "list_id": (IOTS_PREFIXED, "any"),
    },
    "/api/exception_lists/_find": {
        "page": (IOTS_PREFIXED, "any"),
        "per_page": (IOTS_PREFIXED, "any"),
    },
    "/api/exception_lists/items": {
        "id": (IOTS_PREFIXED, "any"),
        "item_id": (IOTS_PREFIXED, "any"),
    },
    "/api/exception_lists/items/_find": {
        "list_id": (IOTS_PREFIXED, "any"),
    },
    "/api/exception_lists/summary": {
        "list_id": (IOTS_PREFIXED, "any"),
    },
    "/api/fleet/agent_policies": {
        "page": (CONFIG, "number"),
        "perPage": (CONFIG, "number"),
    },
    "/api/fleet/agents": {
        "page": (CONFIG, "number"),
        "perPage": (CONFIG, "number"),
    },
    "/api/lists/_find": {
        "page": (ZOD, "number"),
        "per_page": (ZOD, "number"),
    },
    "/api/osquery/packs": {
        "page": (IOTS_PREFIXED, "any"),
    },
    "/api/timeline": {
        "id": (IOTS_PREFIXED, "any"),
        "template_timeline_id": (IOTS_PREFIXED, "any"),
    },
}


def _message(dialect: str, name: str, kind: str, values: list[str]) -> str:
    """The refusal, worded the way that route's validator words it."""
    if dialect == CONFIG:
        return f"[request query.{name}]: expected value of type [{kind}] but got [Array]"
    if dialect == ZOD:
        seen = "received nan" if kind == "number" else "received array"
        expected = "Expected number" if kind == "number" else "Expected string"
        return f"[request query]: {name}: {expected}, {seen}"
    rendered = ",".join(f'"{value}"' for value in values)
    prefix = "[request query]: " if dialect == IOTS_PREFIXED else ""
    return f'{prefix}Invalid value "[{rendered}]" supplied to "{name}"'


def refuse_repeated_query_members(request: Request) -> None:
    """Refuse a repeated scalar query member the way 8.15 refuses it.

    Raises:
        HTTPException: 400, in the route's own validator's words.
    """
    route = request.scope.get("route")
    declared = _REPEATED.get(str(getattr(route, "path", "")))
    if not declared:
        return
    for name, (dialect, kind) in declared.items():
        values = request.query_params.getlist(name)
        if len(values) > 1:
            raise HTTPException(status_code=400, detail=build_kbn_error_response(
                400, _message(dialect, name, kind, values),
            ))
