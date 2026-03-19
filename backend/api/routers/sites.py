from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin
from api.dto.requests import SiteCreateBody, SiteUpdateBody
from application.sites import commands as site_commands
from application.sites import queries as site_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Sites"])


@router.get("/sites")
def list_sites(
    ids: str = Query(None),
    accountIds: str = Query(None),
    states: str = Query(None),
    name: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered list of sites in the S1 allSites envelope format."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return site_queries.list_sites(params, cursor, limit)


@router.get("/sites/{site_id}")
def get_site(site_id: str) -> dict:
    """Return a single site by ID."""
    result = site_queries.get_site(site_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.put("/sites/{site_id}/reactivate")
def reactivate_site(site_id: str, _: dict = Depends(require_admin)) -> dict:
    """Reactivate an expired or decommissioned site.

    Sets state back to ``active`` and clears the expiration date.

    Raises:
        HTTPException: 404 if the site is not found.
    """
    result = site_commands.reactivate_site(site_id)
    if not result:
        raise HTTPException(status_code=404, detail="Site not found")
    return result


@router.post("/sites")
def create_site(body: SiteCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a new site.

    Body: ``{"data": {name, accountId, siteType, suite, sku, totalLicenses, ...}}``
    """
    return site_commands.create_site(body.data)


@router.put("/sites/{site_id}")
def update_site(
    site_id: str,
    body: SiteUpdateBody,
    _: dict = Depends(require_admin),
) -> dict:
    """Update an existing site (partial update — only present fields are changed)."""
    result = site_commands.update_site(site_id, body.data)
    if result is None:
        raise HTTPException(status_code=404, detail="Site not found")
    return result


@router.delete("/sites/{site_id}")
def delete_site(site_id: str, _: dict = Depends(require_admin)) -> dict:
    """Delete a site by ID.

    Raises:
        HTTPException: 404 if the site is not found.
        HTTPException: 400 if the site is the default (cannot be deleted).
    """
    result = site_commands.delete_site(site_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Site not found")
    if result.get("error") == "default":
        raise HTTPException(status_code=400, detail="Cannot delete the default site")
    return result


@router.post("/sites/{site_id}/expire-now")
def expire_site(site_id: str, _: dict = Depends(require_admin)) -> dict:
    """Immediately expire a trial site by setting its state to ``expired``.

    Raises:
        HTTPException: 404 if the site is not found.
    """
    result = site_commands.expire_site(site_id)
    if not result:
        raise HTTPException(status_code=404, detail="Site not found")
    return result
