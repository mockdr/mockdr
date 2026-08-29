"""Kibana Exception Lists API router.

Implements the Elastic Security Exception Lists and Exception Items API
endpoints at ``/api/exception_lists``.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_exception_lists import commands as exc_commands
from application.es_exception_lists import queries as exc_queries
from utils.es_response import build_kbn_error_response, build_security_solution_error
from utils.kibana_query import (
    PREFIXED_INVALID_KEYS,
    refuses_unknown,
)
from utils.kibana_validation import (
    EXCEPTION_NAMESPACES,
    ExceptionListError,
    validate_exception_find_query,
    validate_exception_item_body,
    validate_exception_list_body,
)

router = APIRouter(tags=["ES Exception Lists"])


# ── Exception Lists ──────────────────────────────────────────────────────────


@router.get("/api/exception_lists/_find")
def find_lists(
    request: Request,
    namespace_type: str = Query(None),
    # Untyped on purpose: FastAPI's own 422 would pre-empt the wording this
    # endpoint answers with, which is a third dialect again — io-ts, but with
    # the `[request query]` prefix the Cases API leaves off.
    page: str = Query("1"),
    per_page: str = Query("20"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find exception lists with optional filters and pagination."""
    try:
        validate_exception_find_query(request.query_params)
    except ExceptionListError as exc:
        # The codec answers through Boom; what the search itself refuses —
        # an unknown sort field — comes back in the Security Solution's own
        # envelope. A client branching on the status reads a different member
        # in each.
        raise HTTPException(status_code=400, detail=(
            build_security_solution_error(400, str(exc)) if exc.route_error
            else build_kbn_error_response(400, str(exc))
        )) from exc
    return exc_queries.find_lists(
        namespace_type=namespace_type,
        page=int(float(page)),
        per_page=int(float(per_page)),
    )


# The query schema runs before the handler, so an unknown member is a 400
# naming it — not the "id or list_id required" the handler answers when a
# required one is missing, and not a 200 when the required one *is* there:
# `?list_id=<real>&zzzTypo=1` came back with the list.  Each accepted set
# measured member by member on 8.15.
@router.get(
    "/api/exception_lists",
    dependencies=[refuses_unknown(
        "id", "list_id", "namespace_type",
        dialect=PREFIXED_INVALID_KEYS)],
)
def get_list(
    list_id: str = Query(None),
    id: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single exception list by list_id or id."""
    lookup = list_id or id
    if not lookup:
        raise HTTPException(
            status_code=400,
            # Kibana's own wording, in the Security Solution's envelope
            # rather than Boom's (both measured on 8.15).
            detail=build_security_solution_error(400, "id or list_id required"),
        )
    result = exc_queries.get_list(lookup)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(
                404, f'exception list id: "{lookup}" does not exist',
            ),
        )
    return result


@router.post("/api/exception_lists", dependencies=[Depends(require_kbn_xsrf)])
def create_list(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new exception list.

    The whole body is checked: a `type` outside the enum used to create a
    list here, so a client could keep a type the real Kibana refuses.
    """
    try:
        validate_exception_list_body(body)
    except ExceptionListError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
    return exc_commands.create_list(body)


@router.put("/api/exception_lists", dependencies=[Depends(require_kbn_xsrf)])
def update_list(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update an existing exception list."""
    result = exc_commands.update_list(body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(
                404,
                "Exception list not found",
            ),
        )
    return result


@router.delete("/api/exception_lists", dependencies=[Depends(require_kbn_xsrf)])
def delete_list(
    list_id: str = Query(None),
    id: str = Query(None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete an exception list by list_id or id."""
    lookup = list_id or id
    if not lookup:
        raise HTTPException(
            status_code=400,
            # Kibana's own wording, in the Security Solution's envelope
            # rather than Boom's (both measured on 8.15).
            detail=build_security_solution_error(400, "id or list_id required"),
        )
    deleted = exc_commands.delete_list(lookup)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(
                404, f'exception list id: "{lookup}" does not exist',
            ),
        )
    return {}


# ── Exception Items ──────────────────────────────────────────────────────────


@router.get("/api/exception_lists/items/_find")
def find_items(
    list_id: str = Query(None),
    namespace_type: str = Query(None),
    tags: str = Query(None, description="Comma-separated tags"),
    page: int = Query(1),
    per_page: int = Query(20, ge=0, le=1000),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find exception items with optional filters and pagination.

    ``list_id`` is not optional: without it Kibana refuses the query, where
    mockdr answered with every item it held across every list — a client
    reading one list's exceptions was handed all of them and told they were
    that list's.
    """
    if not list_id:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, '[request query]: Invalid value "undefined" supplied to "list_id"',
        ))
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    try:
        return exc_queries.find_items(
            list_id=list_id,
            namespace_type=namespace_type,
            tags=tag_list,
            page=page,
            per_page=per_page,
        )
    except exc_queries.ExceptionListNotFoundError as exc:
        raise HTTPException(
            status_code=404, detail=build_security_solution_error(404, str(exc)),
        ) from exc


@router.get(
    "/api/exception_lists/items",
    # `item_id` here, where the list route takes `list_id`.
    dependencies=[refuses_unknown(
        "id", "item_id", "namespace_type",
        dialect=PREFIXED_INVALID_KEYS)],
)
def get_item(
    item_id: str = Query(None),
    id: str = Query(None),
    namespace_type: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single exception item by item_id or id."""
    if namespace_type is not None and namespace_type not in EXCEPTION_NAMESPACES:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400,
            f'[request query]: Invalid value "{namespace_type}" '
            'supplied to "namespace_type"',
        ))
    lookup = item_id or id
    if not lookup:
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(400, "id or item_id required"),
        )
    result = exc_queries.get_item(lookup)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, _no_such_item(item_id, id)),
        )
    return result


@router.post("/api/exception_lists/items", dependencies=[Depends(require_kbn_xsrf)])
def create_item(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new exception item.

    Nothing here was checked: an empty body created an item, and so did one
    naming a list that does not exist — an exception nothing could ever
    apply, reported as a success.
    """
    _validated_item(body)
    list_id = str(body.get("list_id", ""))
    if exc_queries.get_list(list_id) is None:
        raise HTTPException(status_code=404, detail=build_security_solution_error(
            404, f'exception list id: "{list_id}" does not exist',
        ))
    item_id = body.get("item_id")
    if item_id and exc_queries.get_item(str(item_id)) is not None:
        raise HTTPException(status_code=409, detail=build_security_solution_error(
            409, f'exception list item id: "{item_id}" already exists',
        ))
    return exc_commands.create_item(body)


@router.put("/api/exception_lists/items", dependencies=[Depends(require_kbn_xsrf)])
def update_item(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update an existing exception item.

    An update that names no item is a 404 here rather than a 400 — the route
    looks the item up first and reports what it could not find, which is what
    a client parses.
    """
    _validated_item(body, update=True)
    if not body.get("id") and not body.get("item_id"):
        raise HTTPException(status_code=404, detail=build_security_solution_error(
            404, "either id or item_id need to be defined",
        ))
    result = exc_commands.update_item(body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(
                404,
                _no_such_item(body.get("item_id"), body.get("id")),
            ),
        )
    return result


@router.delete("/api/exception_lists/items", dependencies=[Depends(require_kbn_xsrf)])
def delete_item(
    item_id: str = Query(None),
    id: str = Query(None),
    _: dict = Depends(require_es_write),
) -> dict:
    """Delete an exception item by item_id or id."""
    lookup = item_id or id
    if not lookup:
        raise HTTPException(
            status_code=400,
            detail=build_security_solution_error(
                400,
                'Either "item_id" or "id" needs to be defined in the request',
            ),
        )
    deleted = exc_commands.delete_item(lookup)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_security_solution_error(404, _no_such_item(item_id, id)),
        )
    return {}


def _require_iots(body: dict, fields: tuple[str, ...]) -> None:
    """Refuse a body missing io-ts-required fields the way Kibana does.

    One ``Invalid value "undefined" supplied to "<field>"`` per missing
    field, comma-joined, in schema order, in the Boom envelope. Measured on
    8.15 for cases and exception lists.
    """
    missing = [f for f in fields if body.get(f) is None]
    if missing:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, ",".join(f'Invalid value "undefined" supplied to "{f}"' for f in missing),
        ))


def _validated_item(body: dict, *, update: bool = False) -> None:
    """Refuse an item body the way Kibana refuses it."""
    try:
        validate_exception_item_body(body, update=update)
    except ExceptionListError as exc:
        raise HTTPException(
            status_code=400, detail=build_kbn_error_response(400, str(exc)),
        ) from exc


def _no_such_item(item_id: object, internal_id: object) -> str:
    """Name the item that could not be found, by whichever id addressed it."""
    if item_id:
        return f'exception list item item_id: "{item_id}" does not exist'
    return f'exception list item id: "{internal_id}" does not exist'
