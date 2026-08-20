"""Kibana Cases API router.

Implements the Elastic Security Cases API endpoints at ``/api/cases``.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import Response

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_cases import commands as case_commands
from application.es_cases import queries as case_queries
from utils.es_response import build_kbn_error_response

router = APIRouter(tags=["ES Cases"])


# ── Find / List ──────────────────────────────────────────────────────────────


@router.get("/api/cases/_find")
def find_cases(
    status: str = Query(None),
    tags: str = Query(None, description="Comma-separated tags"),
    owner: str = Query(None),
    page: int = Query(1),
    per_page: int = Query(20, ge=1, le=1000, alias="perPage"),
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
    """
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    reporter_list = (
        [r.strip() for r in reporters.split(",") if r.strip()] if reporters else None
    )
    return case_queries.find_cases(
        status=status,
        tags=tag_list,
        owner=owner,
        page=page,
        per_page=per_page,
        severity=severity,
        search=search,
        reporters=reporter_list,
        sort_field=sort_field,
        sort_order=sort_order,
    )


@router.get("/api/cases/tags")
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
            detail=build_kbn_error_response(404, f"Case {case_id} not found"),
        )
    return result


@router.post("/api/cases", dependencies=[Depends(require_kbn_xsrf)])
def create_case(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new case."""
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
        case_id = patch.get("id")
        version = patch.get("version")
        if not case_id or not version:
            raise HTTPException(
                status_code=400,
                detail=build_kbn_error_response(
                    400, "each case requires id and version",
                ),
            )

        current = case_queries.get_case(case_id)
        if current is None:
            raise HTTPException(
                status_code=404,
                detail=build_kbn_error_response(404, f"Case {case_id} not found"),
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


@router.delete("/api/cases", dependencies=[Depends(require_kbn_xsrf)])
def delete_cases(
    body: list[str] = Body(...),
    _: dict = Depends(require_es_write),
) -> Response:
    """Delete one or more cases by ID (body is a list of IDs)."""
    for case_id in body:
        case_commands.delete_case(case_id)
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
            detail=build_kbn_error_response(404, f"Case {case_id} not found"),
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
            detail=build_kbn_error_response(404, f"Case {case_id} not found"),
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
    result = case_commands.update_comment(case_id, comment_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404,
                f"Comment {comment_id} not found on case {case_id}",
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
) -> None:
    """Delete a comment from a case."""
    deleted = case_commands.delete_comment(case_id, comment_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_kbn_error_response(
                404,
                f"Comment {comment_id} not found on case {case_id}",
            ),
        )
