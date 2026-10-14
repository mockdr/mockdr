"""CrowdStrike Falcon Cases (Messaging Center) API router.

Implements case management endpoints used by XSOAR for creating,
querying, and tagging support/investigation cases.
"""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Query

from api.cs_auth import require_cs_auth, require_cs_write
from application.cs_cases import commands as case_commands
from application.cs_cases import queries as case_queries

router = APIRouter(tags=["CrowdStrike Cases"])


@router.get("/cases/queries/cases/v1")
def query_case_ids(
    filter: str = Query(None),
    offset: int = Query(0),
    # gofalcon queries_cases_get_v1_parameters.go: "max: 10000"
    limit: int = Query(100, ge=1, le=10000),
    sort: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Query case IDs with optional FQL filter."""
    return case_queries.query_case_ids(filter, offset, limit, sort)


@router.post("/message-center/entities/cases/GET/v1")
def get_cases(
    body: dict = Body(...),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return the case entities named by ``ids``."""
    from utils.cs_response import require_list  # noqa: PLC0415

    return case_queries.get_case_entities([str(i) for i in require_list(body, "ids")])


@router.post("/cases/entities/case-tags/v1")
def add_case_tags(
    body: dict = Body(...),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Add tags to a case.

    Body: ``{"id": "...", "tags": [...]}``.
    """
    case_id = body.get("id", "")
    tags = body.get("tags", [])
    return case_commands.add_case_tags(case_id, tags)


@router.delete("/cases/entities/case-tags/v1")
def delete_case_tags(
    id: str = Query(None),  # noqa: A002 - Falcon's own parameter name
    tag: list[str] = Query(None),
    body: dict | None = Body(None),
    _: dict = Depends(require_cs_write),
) -> dict:
    """Remove tags from a case.

    Falcon takes both in the query string — ``id`` (required) and ``tag``,
    an array with ``collectionFormat: multi`` and also required
    (gofalcon ``entities_case_tags_delete_v1_parameters.go``; falconpy's
    ``entities_case_tags_delete_v1``) — and sends no body, as a DELETE
    usually does not. The route required a JSON body, so every SDK call met
    a 400 for a body it was never going to send. The body form
    ``{"id": "...", "tags": [...]}`` the mock took before is still read
    when the query names nothing.
    """
    if id or tag:
        return case_commands.delete_case_tags(id or "", list(tag or []))
    body = body or {}
    case_id = body.get("id", "")
    tags = body.get("tags", [])
    return case_commands.delete_case_tags(case_id, tags)
