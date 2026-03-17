from fastapi import APIRouter, Query

from application.activities import queries as activity_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Activities"])


@router.get("/activities/types")
def list_activity_types() -> dict:
    """Return the catalogue of all known activity type codes and descriptions."""
    return activity_queries.list_activity_types()


@router.get("/activities")
def list_activities(
    siteIds: str = Query(None),
    userIds: str = Query(None),
    agentIds: str = Query(None),
    activityTypes: str = Query(None),
    createdAt__gte: str = Query(None),
    createdAt__lte: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of activity log entries."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return activity_queries.list_activities(params, cursor, limit)
