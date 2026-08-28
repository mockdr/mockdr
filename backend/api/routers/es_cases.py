"""Kibana Cases API router.

Implements the Elastic Security Cases API endpoints at ``/api/cases``.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import Response

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_cases import commands as case_commands
from application.es_cases import queries as case_queries
from utils.es_response import build_kbn_error_response
from utils.kibana_query import INVALID_KEYS, refuses_unknown
from utils.kibana_validation import (
    CaseBodyError,
    FindQueryError,
    validate_case_body,
    validate_find_query,
)

router = APIRouter(tags=["ES Cases"])


# ── Find / List ──────────────────────────────────────────────────────────────


@router.get("/api/cases/_find")
def find_cases(
    request: Request,
    status: str = Query(None),
    tags: str = Query(None, description="Comma-separated tags"),
    owner: str = Query(None),
    # Untyped on purpose: FastAPI's own 422 would pre-empt Kibana's wording,
    # and the whole point of validating here is to send what Kibana sends.
    page: str = Query("1"),
    per_page: str = Query("20", alias="perPage"),
    severity: str = Query(None),
    search: str = Query(None),
    reporters: str = Query(None, description="Comma-separated usernames"),
    sort_field: str = Query(None, alias="sortField"),
    sort_order: str = Query("desc", alias="sortOrder"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find cases with optional filters and pagination.

    severity, search, reporters, sortField and sortOrder are documented on
    this endpoint but were declared on no parameter, so FastAPI dropped them
    and a filtered request returned the full unfiltered list.

    Kibana validates the whole query before it looks at any data, and mockdr
    accepted almost all of it: `severity=nonsens` came back as 200 with no
    cases, which a client reads as "there are none" rather than as the typo
    it is.
    """
    try:
        validate_find_query(request.query_params)
    except FindQueryError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, str(exc),
        )) from exc
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    reporter_list = (
        [r.strip() for r in reporters.split(",") if r.strip()] if reporters else None
    )
    return case_queries.find_cases(
        status=status,
        tags=tag_list,
        owner=owner,
        page=int(float(page)),
        per_page=int(float(per_page)),
        severity=severity,
        search=search,
        reporters=reporter_list,
        sort_field=sort_field,
        sort_order=sort_order,
    )


@router.get(
    "/api/cases/tags",
    dependencies=[refuses_unknown("owner", dialect=INVALID_KEYS)],
)
def get_tags(
    _: dict = Depends(require_es_auth),
) -> list[str]:
    """Get all unique case tags."""
    return case_queries.get_tags()


# ── Single Case ──────────────────────────────────────────────────────────────


@router.get("/api/cases/{case_id}")
def get_case(
    case_id: str,
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single case by its ID."""
    result = case_queries.get_case(case_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404, f"Saved object [cases/{case_id}] not found",
            ),
        )
    return result


@router.post("/api/cases", dependencies=[Depends(require_kbn_xsrf)])
def create_case(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new case.

    The whole body is checked, not only which members are present: mockdr
    took a severity outside the enum, a title that was a number, and a
    `status` no client may set at creation — all with 200, so the case
    existed and nobody learned of the typo.
    """
    try:
        validate_case_body(body)
    except CaseBodyError as exc:
        status = 403 if exc.forbidden else 400
        raise HTTPException(status_code=status, detail=build_kbn_error_response(
            status, str(exc),
        )) from exc
    return case_commands.create_case(body)


@router.patch("/api/cases", dependencies=[Depends(require_kbn_xsrf)])
def update_cases(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> list[dict]:
    """Update one or more cases.

    This is the endpoint Kibana actually exposes: ``PATCH /api/cases`` with
    ``{"cases": [{id, version, ...}]}``. The mock had it inverted — the bulk
    path 405'd while ``PATCH /api/cases/{id}``, which exists in no Kibana,
    worked. ``version`` is required and a stale one is a conflict, which was
    not enforced at all.
    """
    patches = body.get("cases")
    if not isinstance(patches, list) or not patches:
        raise HTTPException(
            status_code=400,
            detail=build_kbn_error_response(400, "cases: expected a non-empty array"),
        )

    updated: list[dict] = []
    for patch in patches:
        if not isinstance(patch, dict):
            raise HTTPException(
                status_code=400,
                detail=build_kbn_error_response(
                    400, "cases: each entry must be an object",
                ),
            )
        case_id = patch.get("id")
        version = patch.get("version")
        if not case_id or not version:
            raise HTTPException(
                status_code=400,
                detail=build_kbn_error_response(
                    400, 'Invalid value "undefined" supplied to "cases,version"'
                    if case_id else 'Invalid value "undefined" supplied to "cases,id"',
                ),
            )

        current = case_queries.get_case(case_id)
        if current is None:
            raise HTTPException(
                status_code=404,
                detail=build_kbn_error_response(
                404, f"Saved object [cases/{case_id}] not found",
            ),
            )
        if current.get("version") != version:
            raise HTTPException(
                status_code=409,
                detail=build_kbn_error_response(
                    409,
                    f"This case {case_id} has been updated. Please refresh before "
                    f"saving additional updates.",
                ),
            )

        changes = {k: v for k, v in patch.items() if k not in ("id", "version")}
        result = case_commands.update_case(case_id, changes)
        if result is not None:
            updated.append(result)
    return updated


#: Kibana names a JSON type the way JavaScript does, not the way Python does.
_JSON_TYPE_NAMES: dict[type, str] = {
    str: "string", int: "number", float: "number", bool: "boolean",
    dict: "Object", type(None): "null",
}


@router.delete("/api/cases", dependencies=[Depends(require_kbn_xsrf)])
def delete_cases(
    ids: str = Query(None),
    _: dict = Depends(require_es_write),
) -> Response:
    """Delete cases named by ``?ids=["a","b"]``.

    The ids belong in the query string, not the body: Kibana refuses a body
    with the same message it uses for no ids at all, and mockdr read the body
    and answered 204 either way — so a client sending the documented form
    deleted nothing here and everything there.
    """
    if ids is None:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request query.ids]: expected value of type [array] but got [undefined]",
        ))
    try:
        wanted = json.loads(ids)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, f"[request query.ids]: could not parse array value from json input: {ids}",
        )) from exc
    if not isinstance(wanted, list):
        raise HTTPException(status_code=400, detail=build_kbn_error_response(
            400, "[request query.ids]: expected value of type [array] but got "
                 f"[{_JSON_TYPE_NAMES.get(type(wanted), 'Object')}]",
        ))
    for case_id in wanted:
        if not case_commands.delete_case(str(case_id)):
            # A saved object that is not there is a 404 naming it, not a
            # silent success.
            raise HTTPException(status_code=404, detail=build_kbn_error_response(
                404, f"Saved object [cases/{case_id}] not found",
            ))
    return Response(status_code=204)


# ── Comments ─────────────────────────────────────────────────────────────────


@router.get("/api/cases/{case_id}/comments")
def get_case_comments(
    case_id: str,
    _: dict = Depends(require_es_auth),
) -> list[dict]:
    """List all comments for a case."""
    result = case_queries.get_case_comments(case_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404, f"Saved object [cases/{case_id}] not found",
            ),
        )
    return result


@router.post("/api/cases/{case_id}/comments", dependencies=[Depends(require_kbn_xsrf)])
def add_comment(
    case_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Add a comment to a case."""
    result = case_commands.add_comment(case_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404, f"Saved object [cases/{case_id}] not found",
            ),
        )
    return result


@router.patch("/api/cases/{case_id}/comments", dependencies=[Depends(require_kbn_xsrf)])
def update_comment(
    case_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update a comment on a case.

    The request body must include ``id`` (comment ID) and the updated fields.
    """
    comment_id = body.get("id", "")
    try:
        result = case_commands.update_comment(case_id, comment_id, body)
    except case_commands.CaseVersionConflictError as exc:
        raise HTTPException(
            status_code=409, detail=build_kbn_error_response(409, str(exc)),
        ) from exc
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404,
                f"Saved object [cases-comments/{comment_id}] not found",
            ),
        )
    return result


@router.delete(
    "/api/cases/{case_id}/comments/{comment_id}",
    dependencies=[Depends(require_kbn_xsrf)],
)
def delete_comment(
    case_id: str,
    comment_id: str,
    _: dict = Depends(require_es_write),
) -> Response:
    """Delete a comment from a case.

    Kibana answers 204 with an empty body; the route answered 200 and the
    JSON literal ``null``, which a client testing for 204 reads as a failure.
    """
    deleted = case_commands.delete_comment(case_id, comment_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404,
                f"Saved object [cases-comments/{comment_id}] not found",
            ),
        )
    return Response(status_code=204)


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
