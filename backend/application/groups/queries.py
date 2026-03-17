from dataclasses import asdict

from repository.group_repo import group_repo
from utils.filtering import FilterSpec, apply_filters
from utils.internal_fields import GROUP_INTERNAL_FIELDS
from utils.pagination import GROUP_CURSOR, build_list_response, build_single_response, paginate
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("accountIds", "accountId", "in"),
    FilterSpec("siteIds", "siteId", "in"),
    FilterSpec("types", "type", "in"),
    FilterSpec("name", "name", "contains"),
    FilterSpec("updatedAt__gte", "updatedAt", "gte_dt"),
    FilterSpec("updatedAt__lte", "updatedAt", "lte_dt"),
    FilterSpec("updatedAt__gt", "updatedAt", "gte_dt"),
    FilterSpec("updatedAt__lt", "updatedAt", "lte_dt"),
]


def list_groups(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of groups with internal fields stripped."""
    records = [asdict(g) for g in group_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    page, next_cursor, total = paginate(filtered, cursor, limit, GROUP_CURSOR)
    stripped = [strip_fields(r, GROUP_INTERNAL_FIELDS) for r in page]
    return build_list_response(stripped, next_cursor, total)


def get_group(group_id: str) -> dict | None:
    """Return a single group by ID with internal fields stripped, or None."""
    group = group_repo.get(group_id)
    if not group:
        return None
    return build_single_response(strip_fields(asdict(group), GROUP_INTERNAL_FIELDS))
