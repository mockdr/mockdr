from dataclasses import asdict

from repository.site_repo import site_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.internal_fields import SITE_INTERNAL_FIELDS
from utils.pagination import SITE_CURSOR, build_single_response, paginate
from utils.s1_fixtures import complete_s1
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("accountIds", "accountId", "in"),
    FilterSpec("states", "state", "in"),
    FilterSpec("name", "name", "contains"),
]


def list_sites(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered list of sites in the S1 allSites envelope format.

    Real S1 API wraps sites list as ``{"data": {"allSites": {...}, "sites": [...]}}``.
    """
    records = [asdict(s) for s in site_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)
    filtered = apply_query_options(filtered, params)

    # `limit` was ignored and nextCursor hardcoded to None, so a client paging
    # this endpoint received the whole list on page one and was told there was
    # nothing more — SITE_CURSOR existed but nothing used it.
    page, next_cursor, total = paginate(filtered, cursor, limit, SITE_CURSOR)

    sites = [strip_fields(r, SITE_INTERNAL_FIELDS) for r in page]
    # allSites summarises the whole account, not the page.
    all_sites = {
        "activeLicenses": sum(r.get("activeLicenses", 0) for r in filtered),
        "totalLicenses": sum(r.get("totalLicenses", 0) for r in filtered),
    }
    return complete_s1(
        {
            "data": {
                "allSites": all_sites,
                "sites": sites,
            },
            "pagination": {
                "totalItems": total,
                "nextCursor": next_cursor,
            },
        },
        "sites_SiteResponseSchema_200",
    )


def get_site(site_id: str) -> dict | None:
    """Return a single site by ID with internal fields stripped, or None."""
    site = site_repo.get(site_id)
    return build_single_response(strip_fields(asdict(site), SITE_INTERNAL_FIELDS)) if site else None
