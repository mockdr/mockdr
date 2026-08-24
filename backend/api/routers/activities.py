from fastapi import APIRouter, Query
from starlette.requests import Request

from application.activities import queries as activity_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from utils.documented_params import documented_openapi, documented_params

router = APIRouter(tags=["Activities"])


@router.get("/activities/types")
def list_activity_types() -> dict:
    """Return the catalogue of all known activity type codes and descriptions."""
    return activity_queries.list_activity_types()


@router.get("/activities", openapi_extra=documented_openapi("/activities"))
def list_activities(
    request: Request,
    accountIds: str = Query(None),
    siteIds: str = Query(None),
    userIds: str = Query(None),
    userEmails: str = Query(None),  # noqa: N803 - the vendor's own name
    agentIds: str = Query(None),
    activityTypes: str = Query(None),
    createdAt__gte: str = Query(None),
    createdAt__lte: str = Query(None),
    sortBy: str = Query(None),
    sortOrder: str = Query(None),
    skip: int = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of activity log entries."""
    params = {
        k: v for k, v in locals().items()
        if v is not None and k not in ("cursor", "limit", "request")
    }
    params.update(documented_params(request, "/activities"))
    return activity_queries.list_activities(params, cursor, limit)
