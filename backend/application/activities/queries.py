
from repository.activity_repo import activity_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.pagination import ACTIVITY_CURSOR, build_list_response, paginate
from utils.serde import record_dict


def list_activity_types() -> dict:
    """Return the catalogue of all known activity type codes and descriptions.

    Returns:
        Dict with ``data`` list of ``{id, action}`` records.
    """
    from infrastructure.seeders._shared import ACTIVITY_CATALOG

    # activity types carry id, action and a descriptionTemplate (2.1 swagger)
    return {"data": [{"id": t, "action": d, "descriptionTemplate": d} for t, d in ACTIVITY_CATALOG]}


FILTER_SPECS = [
    FilterSpec("siteIds", "siteId", "in"),
    FilterSpec("accountIds", "accountId", "in"),
    FilterSpec("userIds", "userId", "in"),
    FilterSpec("agentIds", "agentId", "in"),
    FilterSpec("activityTypes", "activityType", "in"),
    FilterSpec("createdAt__gte", "createdAt", "gte_dt"),
    FilterSpec("createdAt__lte", "createdAt", "lte_dt"),
]


def list_activities(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of activity log entries."""
    # agentId must be a string (not None) per the S1 API schema;
    # other nullable fields (osFamily, description, etc.) may remain None.
    string_fields = {"agentId", "agentUpdatedVersion", "threatId", "hash"}
    raw = [
        {**record_dict(a), "activityType": int(a.activityType)}
        for a in activity_repo.list_all()
    ]
    records = [
        {k: ("" if v is None and k in string_fields else v) for k, v in r.items()} for r in raw
    ]
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: r.get("id", 0))
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, ACTIVITY_CURSOR)
    return build_list_response(page, next_cursor, total, definition="_ActivityViewSchema_many_200")
