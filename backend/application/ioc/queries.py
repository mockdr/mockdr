from dataclasses import asdict

from repository.ioc_repo import ioc_repo
from utils.filtering import FilterSpec, apply_filters
from utils.pagination import IOC_CURSOR, build_list_response, paginate

FILTER_SPECS = [
    FilterSpec("ids", "uuid", "in"),
    FilterSpec("types", "type", "in"),
    FilterSpec("sources", "source", "in"),
    FilterSpec("value", "value", "contains"),
]


def list_iocs(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of IOCs sorted by creation date."""
    records = [asdict(i) for i in ioc_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: r.get("creationTime", ""), reverse=True)
    page, next_cursor, total = paginate(filtered, cursor, limit, IOC_CURSOR)
    return build_list_response(page, next_cursor, total)
