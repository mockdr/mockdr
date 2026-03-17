from dataclasses import asdict

from repository.exclusion_repo import exclusion_repo
from utils.filtering import FilterSpec, apply_filters
from utils.internal_fields import EXCLUSION_INTERNAL_FIELDS
from utils.pagination import EXCLUSION_CURSOR, build_list_response, paginate
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("siteIds", "siteId", "in"),   # internal field, used for filtering only
    FilterSpec("types", "type", "in"),
    FilterSpec("osTypes", "osType", "in"),
]


def list_exclusions(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of exclusions with internal fields stripped."""
    records = [asdict(e) for e in exclusion_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)  # filter before strip
    page, next_cursor, total = paginate(filtered, cursor, limit, EXCLUSION_CURSOR)
    stripped = [strip_fields(r, EXCLUSION_INTERNAL_FIELDS) for r in page]
    return build_list_response(stripped, next_cursor, total)
