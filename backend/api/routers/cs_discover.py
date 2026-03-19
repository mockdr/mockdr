"""CrowdStrike Falcon Discover API router.

Implements the Discover module's application inventory endpoint, which
provides a combined view of installed applications across all hosts.
Data is derived from the canonical ``installed_apps`` store, translated
into CrowdStrike Discover format.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.cs_auth import require_cs_auth
from application.cs_discover import queries as discover_queries

router = APIRouter(tags=["CrowdStrike Discover"])


@router.get("/discover/combined/applications/v1")
def combined_applications(
    filter: str = Query(None),
    limit: int = Query(100, le=100),
    offset: int = Query(0),
    sort: str = Query(None),
    after: str = Query(None),
    _: dict = Depends(require_cs_auth),
) -> dict:
    """Return installed applications across all hosts in Discover format.

    Supports cursor-based pagination via the ``after`` parameter (returned
    in ``meta.pagination.after`` of the previous response).  Falls back to
    offset-based pagination when ``after`` is not provided.
    """
    return discover_queries.combined_applications(filter, limit, offset, sort, after)
