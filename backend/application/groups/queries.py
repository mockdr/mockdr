
from repository.group_repo import group_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.internal_fields import GROUP_INTERNAL_FIELDS
from utils.pagination import GROUP_CURSOR, build_list_response, build_single_response, paginate
from utils.s1_fixtures import restrict_s1
from utils.serde import record_dict
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("id", "id", "in"),  # the swagger's own name, beside this mock's plural
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
    filtered = apply_filters(group_repo.list_all(), params, FILTER_SPECS)
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, GROUP_CURSOR)
    stripped = [strip_fields(record_dict(g), GROUP_INTERNAL_FIELDS) for g in page]
    return build_list_response(
        stripped, next_cursor, total, definition="groups_SummarizedGroupSchema_many_200"
    )


def get_group(group_id: str) -> dict | None:
    """Return a single group by ID with internal fields stripped, or None."""
    group = group_repo.get(group_id)
    if not group:
        return None
    return restrict_s1(
        build_single_response(strip_fields(record_dict(group), GROUP_INTERNAL_FIELDS)),
        "groups_GroupSchema_200",
    )
