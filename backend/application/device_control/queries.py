
from application.documented_filters import DOCUMENTED_FILTERS
from repository.device_control_repo import device_control_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.internal_fields import DEVICE_CONTROL_INTERNAL_FIELDS
from utils.pagination import DEVICE_CTRL_CURSOR, build_list_response, paginate
from utils.serde import record_dict
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("siteIds", "siteId", "in"),
    FilterSpec("actions", "action", "in"),
    FilterSpec("statuses", "status", "in"),
    FilterSpec("deviceClasses", "deviceClass", "in"),
    # S1 spells the interface class "deviceTypes" on the query string.
    FilterSpec("deviceTypes", "interface", "in"),
]


def list_rules(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of device control rules."""
    filtered = apply_filters(
        device_control_repo.list_all(),
        params,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/device-control", []),
    )
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, DEVICE_CTRL_CURSOR)
    stripped = [strip_fields(record_dict(r), DEVICE_CONTROL_INTERNAL_FIELDS) for r in page]
    return build_list_response(
        stripped, next_cursor, total, definition="device_control.schemas_DeviceSchema_many_200"
    )
