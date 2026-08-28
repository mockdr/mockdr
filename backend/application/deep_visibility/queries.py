from datetime import UTC, datetime

from config import DV_FINISH_DELAY_SECONDS
from repository.dv_query_repo import dv_query_repo
from utils.pagination import build_list_response, paginate

#: The mode a Deep Visibility query ran in. `queryModeInfo` is on every
#: status the 2.1 swagger declares, and this answered neither it nor
#: `warnings` — while answering a `queryId` and a `status` the swagger
#: declares nowhere, the second of them a duplicate of `responseState` under
#: a name the vendor does not use.
_QUERY_MODE = "scalyr"


def _status_body(state: str, progress: int, activated_at: str = "") -> dict:
    """The status body `DvQueryStatusResponse` declares.

    `lastActivatedAt` is a `date-time` string in the swagger, so the mode
    carries when it was last active — which for this install is when the
    query it belongs to started.
    """
    body: dict = {
        "responseState": state,
        "progressStatus": progress,
        "queryModeInfo": {"mode": _QUERY_MODE, "lastActivatedAt": activated_at},
        # The swagger declares this a string, not a list.
        "warnings": "",
    }
    if state in ("FAILED", "FAILED_CLIENT"):
        # The swagger says so: relevant only for these two.
        body["responseError"] = ""
    return body


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
        return {"data": _status_body(query.status, progress, query.createdAt)}
    return {"data": _status_body(query.status, 100, query.createdAt)}


def get_events(
    query_id: str,
    cursor: str | None,
    limit: int,
    *,
    event_type: str | None = None,
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
    return build_list_response(
        page,
        next_cursor,
        total,
        definition="deep_visibility.deep_visibility_v2_schemas_DeepVisibilityEventEntitySchema_many_200",
    )
