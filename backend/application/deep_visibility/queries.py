from datetime import UTC, datetime

from config import DV_FINISH_DELAY_SECONDS
from repository.dv_query_repo import dv_query_repo
from utils.pagination import build_list_response, paginate


def get_query_status(query_id: str) -> dict | None:
    """Return the current status and progress of a Deep Visibility query.

    Automatically transitions RUNNING queries to FINISHED once the configured
    delay has elapsed.

    Args:
        query_id: The ID of the query to check.

    Returns:
        Status dict, or None if the query does not exist.
    """
    query = dv_query_repo.get(query_id)
    if not query:
        return None
    if query.status == "RUNNING":
        created = datetime.strptime(query.createdAt, "%Y-%m-%dT%H:%M:%S.000Z").replace(tzinfo=UTC)
        elapsed = (datetime.now(UTC) - created).total_seconds()
        progress = min(100, int(elapsed / DV_FINISH_DELAY_SECONDS * 100))
        if elapsed >= DV_FINISH_DELAY_SECONDS:
            query.status = "FINISHED"
            dv_query_repo.save(query)
            progress = 100
        return {"data": {
            "queryId": query_id,
            "responseState": query.status,
            "progressStatus": progress,
            "status": query.status,
        }}
    return {"data": {
        "queryId": query_id,
        "responseState": query.status,
        "progressStatus": 100,
        "status": query.status,
    }}


def get_events(
    query_id: str, cursor: str | None, limit: int,
    *, event_type: str | None = None,
) -> dict | None:
    """Return a paginated list of events for a completed Deep Visibility query.

    Args:
        query_id: The ID of the query whose events to retrieve.
        cursor: Pagination cursor from a previous response.
        limit: Maximum number of events to return.
        event_type: Optional event type to filter by.

    Returns:
        Paginated event list, or None if the query does not exist.
    """
    query = dv_query_repo.get(query_id)
    if not query:
        return None
    events = query.events
    if event_type:
        events = [e for e in events if e.get("eventType") == event_type]
    page, next_cursor, total = paginate(events, cursor, limit)
    return build_list_response(page, next_cursor, total)
