from dataclasses import asdict

from repository.site_repo import site_repo
from utils.filtering import FilterSpec, apply_filters
from utils.internal_fields import SITE_INTERNAL_FIELDS
from utils.pagination import build_single_response
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
    total = len(filtered)
    sites = [strip_fields(r, SITE_INTERNAL_FIELDS) for r in filtered]
    all_sites = {
        "activeLicenses": sum(r.get("activeLicenses", 0) for r in filtered),
        "totalLicenses": sum(r.get("totalLicenses", 0) for r in filtered),
    }
    return {
        "data": {
            "allSites": all_sites,
            "sites": sites,
        },
        "pagination": {
            "totalItems": total,
            "nextCursor": None,
        },
    }


def get_site(site_id: str) -> dict | None:
    """Return a single site by ID with internal fields stripped, or None."""
    site = site_repo.get(site_id)
    return build_single_response(strip_fields(asdict(site), SITE_INTERNAL_FIELDS)) if site else None
