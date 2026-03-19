"""Kibana Exception Lists API router.

Implements the Elastic Security Exception Lists and Exception Items API
endpoints at ``/api/exception_lists``.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query

from api.es_auth import require_es_auth, require_es_write, require_kbn_xsrf
from application.es_exception_lists import commands as exc_commands
from application.es_exception_lists import queries as exc_queries
from utils.es_response import build_es_error_response

router = APIRouter(tags=["ES Exception Lists"])


# ── Exception Lists ──────────────────────────────────────────────────────────


@router.get("/api/exception_lists/_find")
def find_lists(
    list_id: str = Query(None),
    namespace_type: str = Query(None),
    page: int = Query(1),
    per_page: int = Query(20, ge=1, le=1000),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find exception lists with optional filters and pagination."""
    return exc_queries.find_lists(
        list_id=list_id, namespace_type=namespace_type,
        page=page, per_page=per_page,
    )


@router.get("/api/exception_lists")
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
            detail=build_es_error_response(
                400, "bad_request",
                "Either list_id or id query parameter is required",
            ),
        )
    result = exc_queries.get_list(lookup)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(
                404, "not_found", f"Exception list {lookup} not found",
            ),
        )
    return result


@router.post("/api/exception_lists", dependencies=[Depends(require_kbn_xsrf)])
def create_list(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new exception list."""
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
            detail=build_es_error_response(
                404, "not_found", "Exception list not found",
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
            detail=build_es_error_response(
                400, "bad_request",
                "Either list_id or id query parameter is required",
            ),
        )
    deleted = exc_commands.delete_list(lookup)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(
                404, "not_found", f"Exception list {lookup} not found",
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
    per_page: int = Query(20, ge=1, le=1000),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Find exception items with optional filters and pagination."""
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else None
    return exc_queries.find_items(
        list_id=list_id, namespace_type=namespace_type, tags=tag_list,
        page=page, per_page=per_page,
    )


@router.get("/api/exception_lists/items")
def get_item(
    item_id: str = Query(None),
    id: str = Query(None),
    _: dict = Depends(require_es_auth),
) -> dict:
    """Get a single exception item by item_id or id."""
    lookup = item_id or id
    if not lookup:
        raise HTTPException(
            status_code=400,
            detail=build_es_error_response(
                400, "bad_request",
                "Either item_id or id query parameter is required",
            ),
        )
    result = exc_queries.get_item(lookup)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(
                404, "not_found", f"Exception item {lookup} not found",
            ),
        )
    return result


@router.post("/api/exception_lists/items", dependencies=[Depends(require_kbn_xsrf)])
def create_item(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Create a new exception item."""
    return exc_commands.create_item(body)


@router.put("/api/exception_lists/items", dependencies=[Depends(require_kbn_xsrf)])
def update_item(
    body: dict = Body(...),
    _: dict = Depends(require_es_write),
) -> dict:
    """Update an existing exception item."""
    result = exc_commands.update_item(body)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(
                404, "not_found", "Exception item not found",
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
            detail=build_es_error_response(
                400, "bad_request",
                "Either item_id or id query parameter is required",
            ),
        )
    deleted = exc_commands.delete_item(lookup)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=build_es_error_response(
                404, "not_found", f"Exception item {lookup} not found",
            ),
        )
    return {}
