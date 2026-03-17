from domain.dv_query import DVQuery
from infrastructure.dv_gen import generate_dv_events
from repository.activity_repo import activity_repo
from repository.dv_query_repo import dv_query_repo
from utils.dt import utc_now
from utils.id_gen import new_id


def init_query(body: dict, user_id: str | None) -> dict:
    """Create and persist a new Deep Visibility query with pre-seeded events.

    Args:
        body: Request body containing ``query``, ``fromDate``, and ``toDate``.
        user_id: ID of the initiating user, if authenticated.

    Returns:
        Dict with ``data.queryId`` for the newly created query.
    """
    query_id = new_id()
    query = DVQuery(
        id=query_id,
        query=body.get("query", ""),
        fromDate=body.get("fromDate", ""),
        toDate=body.get("toDate", ""),
        status="RUNNING",
        createdAt=utc_now(),
        events=generate_dv_events(count=50, query_body=body),
    )
    dv_query_repo.save(query)
    activity_repo.create(2001, "Deep Visibility query initiated", user_id=user_id)
    return {"data": {"queryId": query_id}}


def cancel_query(query_id: str) -> dict:
    """Cancel a running Deep Visibility query.

    Args:
        query_id: The ID of the query to cancel.

    Returns:
        Dict with ``data.affected`` (1 if cancelled, 0 if not found).
    """
    query = dv_query_repo.get(query_id)
    if not query:
        return {"data": {"affected": 0}}
    query.status = "CANCELLED"
    dv_query_repo.save(query)
    return {"data": {"affected": 1}}
