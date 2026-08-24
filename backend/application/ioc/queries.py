
from application.documented_filters import DOCUMENTED_FILTERS
from repository.ioc_repo import ioc_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.nested import get_nested
from utils.pagination import IOC_CURSOR, build_list_response, paginate
from utils.serde import record_dict

FILTER_SPECS = [
    FilterSpec("ids", "uuid", "in"),
    # The swagger's own names beside this mock's plurals; `type` is declared
    # with an enum (DNS, IPV4, …) that the records already spell that way.
    FilterSpec("uuids", "uuid", "in"),
    FilterSpec("type", "type", "in", enum=True),
    FilterSpec("source", "source", "in"),
    FilterSpec("types", "type", "in"),
    FilterSpec("sources", "source", "in"),
    FilterSpec("value", "value", "contains"),
]


def list_iocs(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of IOCs sorted by creation date."""
    filtered = apply_filters(
        ioc_repo.list_all(),
        params,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/threat-intelligence/iocs", []),
    )
    filtered.sort(key=lambda i: get_nested(i, "creationTime") or "", reverse=True)
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, IOC_CURSOR)
    return build_list_response(
        [record_dict(i) for i in page],
        next_cursor,
        total,
        definition="v2_1.schemas_GetIndicatorSchema_many_200",
    )
