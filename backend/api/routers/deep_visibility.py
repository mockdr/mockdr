from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_auth
from api.dto.requests import DvInitQueryBody
from application.deep_visibility import commands as dv_commands
from application.deep_visibility import queries as dv_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Deep Visibility"])


@router.post("/dv/init-query")
def init_query(body: DvInitQueryBody, current_user: dict = Depends(require_auth)) -> dict:
    """Initialise a new Deep Visibility query and return its ID."""
    return dv_commands.init_query(body.model_dump(), current_user.get("userId"))


@router.get("/dv/query-status")
def query_status(
    queryId: str = Query(None),
) -> dict:
    """Return the current status and progress of a Deep Visibility query."""
    if not queryId:
        raise HTTPException(status_code=422, detail="queryId required")
    result = dv_queries.get_query_status(queryId)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.get("/dv/events")
def get_events(
    queryId: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a paginated list of events for a Deep Visibility query."""
    if not queryId:
        raise HTTPException(status_code=422, detail="queryId required")
    result = dv_queries.get_events(queryId, cursor, limit)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.get("/dv/events/{event_type}")
def get_events_by_type(
    event_type: str,
    queryId: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return events of a specific type for a Deep Visibility query."""
    if not queryId:
        raise HTTPException(status_code=422, detail="queryId required")
    result = dv_queries.get_events(queryId, None, limit, event_type=event_type)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.post("/dv/cancel-query")
def cancel_query(body: dict, _: dict = Depends(require_auth)) -> dict:
    """Cancel a running Deep Visibility query.

    Accepts both flat ``{"queryId": "..."}`` and wrapped ``{"data": {"queryId": "..."}}`` payloads.
    """
    data = body.get("data") or body
    query_id = data.get("queryId", "")
    if not query_id:
        raise HTTPException(status_code=400, detail="queryId is required")
    return dv_commands.cancel_query(query_id)
