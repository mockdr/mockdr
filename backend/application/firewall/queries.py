from dataclasses import asdict

from repository.firewall_repo import firewall_repo
from utils.filtering import FilterSpec, apply_filters
from utils.internal_fields import FIREWALL_INTERNAL_FIELDS
from utils.pagination import FIREWALL_CURSOR, build_list_response, paginate
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("siteIds", "siteId", "in"),   # internal field, used for filtering only
    FilterSpec("statuses", "status", "in"),
    FilterSpec("actions", "action", "in"),
]


def list_rules(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of firewall rules sorted by order."""
    records = [asdict(r) for r in firewall_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)  # filter before strip
    filtered.sort(key=lambda r: r.get("order", 0))
    page, next_cursor, total = paginate(filtered, cursor, limit, FIREWALL_CURSOR)
    stripped = [strip_fields(r, FIREWALL_INTERNAL_FIELDS) for r in page]
    return build_list_response(stripped, next_cursor, total)
