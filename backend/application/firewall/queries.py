
from repository.firewall_repo import firewall_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.internal_fields import FIREWALL_INTERNAL_FIELDS
from utils.nested import get_nested
from utils.pagination import FIREWALL_CURSOR, build_list_response, paginate
from utils.serde import record_dict
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("siteIds", "siteId", "in"),  # internal field, used for filtering only
    FilterSpec("statuses", "status", "in"),
    FilterSpec("actions", "action", "in"),
]


def list_rules(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of firewall rules sorted by order."""
    filtered = apply_filters(firewall_repo.list_all(), params, FILTER_SPECS)  # before strip
    filtered.sort(key=lambda r: get_nested(r, "order") or 0)
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, FIREWALL_CURSOR)
    stripped = [strip_fields(record_dict(r), FIREWALL_INTERNAL_FIELDS) for r in page]
    return build_list_response(
        stripped, next_cursor, total, definition="firewall_control.schemas_FirewallSchema_many_200"
    )
