from dataclasses import asdict

from repository.exclusion_repo import exclusion_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.internal_fields import EXCLUSION_INTERNAL_FIELDS
from utils.pagination import EXCLUSION_CURSOR, build_list_response, paginate
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("value__contains", "value", "contains"),
    FilterSpec("ids", "id", "in"),
    FilterSpec("siteIds", "siteId", "in"),  # internal field, used for filtering only
    FilterSpec("types", "type", "in"),
    FilterSpec("osTypes", "osType", "in"),
]


def _api_scope(record: dict) -> dict:
    """The scope as ExclusionSchemaGet declares it: id lists per level plus ``tenant``.

    The record keeps the compact ``{"tenant": True}`` / ``{"siteId": "…"}`` form.
    """
    raw = record.get("scope")
    scope: dict = raw if isinstance(raw, dict) else {}
    site = scope.get("siteId") or record.get("siteId")
    return {
        **record,
        "scope": {
            "tenant": bool(scope.get("tenant", False)),
            "accountIds": list(scope.get("accountIds", [])),
            "siteIds": [site] if site else list(scope.get("siteIds", [])),
            "groupIds": list(scope.get("groupIds", [])),
        },
    }


def list_exclusions(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of exclusions with internal fields stripped."""
    records = [asdict(e) for e in exclusion_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)  # filter before strip
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, EXCLUSION_CURSOR)
    stripped = [_api_scope(strip_fields(r, EXCLUSION_INTERNAL_FIELDS)) for r in page]
    return build_list_response(
        stripped,
        next_cursor,
        total,
        definition="exclusions.schemas_ExclusionSchemaGet_many_200",
        strict=True,
    )
