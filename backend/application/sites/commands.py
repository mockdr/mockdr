"""Write-side command handlers for Site CRUD.

POST /sites   → create_site
PUT  /sites/{id} → update_site
DELETE /sites/{id} → delete_site
"""
from dataclasses import asdict

from application.accounts.commands import decrement_site_count, increment_site_count
from domain.site import Site
from repository.account_repo import account_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import SITE_INTERNAL_FIELDS
from utils.strip import strip_fields


def create_site(data: dict) -> dict:
    """Create a new site and persist it to the store.

    Args:
        data: Inner data dict from the S1-style ``{"data": {...}}`` request body.
              Required: name, accountId, siteType, suite, sku, totalLicenses.
              Optional: description, expiration, unlimitedExpiration,
              unlimitedLicenses, externalId, inheritAccountExpiration, usageType.

    Returns:
        Dict with ``data`` containing the created site record (internal fields stripped).
    """
    now = utc_now()
    account_id: str = data.get("accountId", "")
    account = account_repo.get(account_id)
    account_name: str = account.name if account else ""

    site = Site(
        id=new_id(),
        name=data.get("name", ""),
        accountId=account_id,
        accountName=account_name,
        state="active",
        activeLicenses=0,
        totalLicenses=int(data.get("totalLicenses", 0)),
        createdAt=now,
        updatedAt=now,
        registrationToken=new_id(),
        siteType=data.get("siteType", "Paid"),
        sku=data.get("sku", "Complete"),
        suite=data.get("suite", "Complete"),
        healthStatus=True,
        isDefault=False,
        expiration=data.get("expiration"),
        unlimitedExpiration=bool(data.get("unlimitedExpiration", False)),
        unlimitedLicenses=bool(data.get("unlimitedLicenses", False)),
        description=data.get("description"),
        externalId=data.get("externalId"),
        inheritAccountExpiration=data.get("inheritAccountExpiration"),
        usageType=data.get("usageType"),
    )
    site_repo.save(site)
    increment_site_count(account_id)
    return {"data": strip_fields(asdict(site), SITE_INTERNAL_FIELDS)}


def update_site(site_id: str, data: dict) -> dict | None:
    """Apply a partial update to an existing site.

    Args:
        site_id: The site's unique identifier.
        data: Inner data dict from the S1-style ``{"data": {...}}`` request body.
              All fields are optional; only present keys are overwritten.

    Returns:
        Dict with ``data`` containing the updated site, or None if not found.
    """
    site = site_repo.get(site_id)
    if not site:
        return None

    updatable = (
        "name", "description", "siteType", "suite", "sku",
        "totalLicenses", "expiration", "unlimitedExpiration",
        "unlimitedLicenses", "externalId", "inheritAccountExpiration",
        "usageType", "state",
    )
    for field in updatable:
        if field in data:
            setattr(site, field, data[field])
    site.updatedAt = utc_now()
    site_repo.save(site)
    return {"data": strip_fields(asdict(site), SITE_INTERNAL_FIELDS)}


def reactivate_site(site_id: str) -> dict | None:
    """Set a site's state back to active and clear its expiration date.

    Args:
        site_id: The site's unique identifier.

    Returns:
        Dict with ``data`` containing the updated site, or None if not found.
    """
    site = site_repo.get(site_id)
    if not site:
        return None
    site.state = "active"
    site.expiration = None
    site.updatedAt = utc_now()
    site_repo.save(site)
    return {"data": strip_fields(asdict(site), SITE_INTERNAL_FIELDS)}


def expire_site(site_id: str) -> dict | None:
    """Immediately expire a trial site by setting its state to ``expired``.

    Args:
        site_id: The site's unique identifier.

    Returns:
        Dict with ``data`` containing the updated site, or None if not found.
    """
    site = site_repo.get(site_id)
    if not site:
        return None
    now = utc_now()
    site.state = "expired"
    site.expiration = now
    site.updatedAt = now
    site_repo.save(site)
    return {"data": strip_fields(asdict(site), SITE_INTERNAL_FIELDS)}


def delete_site(site_id: str) -> dict | None:
    """Delete a site by ID.

    Refuses to delete the default site.

    Args:
        site_id: The site's unique identifier.

    Returns:
        Dict with ``data.success`` True on success,
        ``{"error": "default"}`` if the site is the default site,
        or None if not found.
    """
    site = site_repo.get(site_id)
    if not site:
        return None
    if site.isDefault:
        return {"error": "default"}

    # Cascade: delete associated groups
    for group in group_repo.get_by_site(site_id):
        group_repo.delete(group.id)

    # Cascade: clear site reference on agents belonging to this site
    for agent in agent_repo.list_all():
        if agent.siteId == site_id:
            agent.siteId = ""
            agent.siteName = ""
            agent.groupId = ""
            agent.groupName = ""
            agent_repo.save(agent)

    site_repo.delete(site_id)
    decrement_site_count(site.accountId)
    return {"data": {"success": True}}
