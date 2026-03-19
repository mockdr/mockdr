"""Kibana Cases API router.

Implements the Elastic Security Cases API endpoints at ``/api/cases``.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import Response

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_cases import commands as case_commands
from application.es_cases import queries as case_queries
from utils.es_response import build_es_error_response

router = APIRouter(tags=["ES Cases"])


# ── Find / List ──────────────────────────────────────────────────────────────


@router.get("/api/cases/_find")
def find_cases(
    status: str = Query(None),
    tags: str = Query(None, description="Comma-separated tags"),
    owner: str = Query(None),
    page: int = Query(1),
    per_page: int = Query(20, ge=1, le=1000, alias="perPage"),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find cases with optional filters and pagination."""
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    return case_queries.find_cases(
        status=status, tags=tag_list, owner=owner,
        page=page, per_page=per_page,
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
            detail=build_es_error_response(404, "not_found", f"Case {case_id} not found"),
        )
    return result


@router.post("/api/cases", dependencies=[Depends(require_kbn_xsrf)])
def create_case(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new case."""
    return case_commands.create_case(body)


@router.patch("/api/cases/{case_id}", dependencies=[Depends(require_kbn_xsrf)])
def update_case(
    case_id: str,
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update an existing case (Kibana uses PATCH)."""
    result = case_commands.update_case(case_id, body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(404, "not_found", f"Case {case_id} not found"),
        )
    return result


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
            detail=build_es_error_response(404, "not_found", f"Case {case_id} not found"),
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
            detail=build_es_error_response(404, "not_found", f"Case {case_id} not found"),
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
            detail=build_es_error_response(
                404, "not_found",
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
            detail=build_es_error_response(
                404, "not_found",
                f"Comment {comment_id} not found on case {case_id}",
            ),
        )
