"""Write-side command handlers for Site CRUD.

POST /sites   → create_site
PUT  /sites/{id} → update_site
DELETE /sites/{id} → delete_site
"""

from application.accounts.commands import resync_account_totals
from domain.site import Site
from repository.account_repo import account_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import SITE_INTERNAL_FIELDS
from utils.serde import record_dict
from utils.strip import strip_fields


class InvalidSiteError(ValueError):
    """A site body this route cannot make a site out of."""


def _whole_licenses(value: object) -> int:
    """`totalLicenses` as a whole number, or a refusal saying it is not one.

    `int(data.get("totalLicenses", 0))` raised out of the handler for a
    string that is not a number, and for a dict or a list. A 500 tells the
    client the server is broken and to retry the same body; the request is
    what is wrong, and a 400 says so.
    """
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        msg = "data.totalLicenses must be a number"
        raise InvalidSiteError(msg)
    if not isinstance(value, (int, float, str)):
        msg = "data.totalLicenses must be a number"
        raise InvalidSiteError(msg)
    try:
        return int(value)
    except (ValueError, OverflowError):
        msg = "data.totalLicenses must be a number"
        raise InvalidSiteError(msg) from None


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
    licenses = _whole_licenses(data.get("totalLicenses", 0))
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
        totalLicenses=licenses,
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
    resync_account_totals(account_id)
    return {"data": strip_fields(record_dict(site), SITE_INTERNAL_FIELDS)}


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
    # `totalLicenses` is one of the members above, and the account sums it.
    resync_account_totals(site.accountId)
    return {"data": strip_fields(record_dict(site), SITE_INTERNAL_FIELDS)}


def reactivate_site(site_id: str, data: dict | None = None) -> dict | None:
    """Set a site's state back to active, with the expiration it was given.

    The swagger documents two members on this body: `unlimited`, whose
    description reads "if false an expiration should be supplied", and
    `expiration`, "new expiration date for the site". This route took no body
    at all and always cleared the expiration — the opposite of what the two
    members are for, and a 200 either way, so a client reactivating a site
    for another year was given one with no expiry and told it had worked.

    Args:
        site_id: The site's unique identifier.
        data: The body's `data` payload, if one was sent.

    Returns:
        Dict with ``data`` containing the updated site, or None if not found.
    """
    site = site_repo.get(site_id)
    if not site:
        return None
    payload = data or {}
    site.state = "active"
    if payload.get("unlimited"):
        site.expiration = None
        site.unlimitedExpiration = True
    elif payload.get("expiration"):
        site.expiration = payload["expiration"]
        site.unlimitedExpiration = False
    else:
        # No body, which is how this route has always been called here.
        site.expiration = None
    site.updatedAt = utc_now()
    site_repo.save(site)
    return {"data": strip_fields(record_dict(site), SITE_INTERNAL_FIELDS)}


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
    return {"data": strip_fields(record_dict(site), SITE_INTERNAL_FIELDS)}


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
    resync_account_totals(site.accountId)
    return {"data": {"success": True}}
