
from repository.ioc_repo import ioc_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
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
    records = [record_dict(i) for i in ioc_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered.sort(key=lambda r: r.get("creationTime", ""), reverse=True)
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, IOC_CURSOR)
    return build_list_response(
        page, next_cursor, total, definition="v2_1.schemas_GetIndicatorSchema_many_200"
    )
