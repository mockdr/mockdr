"""Write-side command handlers for Account CRUD.

POST /accounts      → create_account
PUT  /accounts/{id} → update_account
"""

from domain.account import Account
from repository.account_repo import account_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.serde import record_dict


def create_account(data: dict) -> dict:
    """Create a new account and persist it to the store.

    Args:
        data: Inner data dict from the S1-style ``{"data": {...}}`` request body.
              Required: name.
              Optional: accountType, expiration.

    Returns:
        Dict with ``data`` containing the created account record.
    """
    now = utc_now()
    account = Account(
        id=new_id(),
        name=data.get("name", ""),
        createdAt=now,
        updatedAt=now,
        state="active",
        numberOfSites=0,
        numberOfAgents=0,
        activeAgents=0,
        numberOfUsers=0,
        accountType=data.get("accountType", "Trial"),
        isDefault=False,
        expiration=data.get("expiration"),
        # The rest of what `POST /accounts` documents and this record holds.
        # They were left out, so a create naming a billing mode was answered
        # 200 with the swagger's example instead.
        billingMode=data.get("billingMode", "subscription"),
        usageType=data.get("usageType", "customer"),
        externalId=data.get("externalId", ""),
        salesforceId=data.get("salesforceId", ""),
        unlimitedExpiration=bool(data.get("unlimitedExpiration", False)),
        makeSocDefaultUi=bool(data.get("makeSocDefaultUi", False)),
    )
    account_repo.save(account)
    return {"data": record_dict(account)}


def increment_site_count(account_id: str) -> None:
    """Increment the numberOfSites counter on an account.

    Args:
        account_id: The account's unique identifier.
    """
    account = account_repo.get(account_id)
    if account:
        account.numberOfSites = (account.numberOfSites or 0) + 1
        account_repo.save(account)


def decrement_site_count(account_id: str) -> None:
    """Decrement the numberOfSites counter on an account.

    Args:
        account_id: The account's unique identifier.
    """
    account = account_repo.get(account_id)
    if account:
        account.numberOfSites = max(0, (account.numberOfSites or 0) - 1)
        account_repo.save(account)


def update_account(account_id: str, data: dict) -> dict | None:
    """Apply a partial update to an existing account.

    Args:
        account_id: The account's unique identifier.
        data: Inner data dict from the S1-style ``{"data": {...}}`` request body.
              All fields optional; only present keys are overwritten.

    Returns:
        Dict with ``data`` containing the updated account, or None if not found.
    """
    account = account_repo.get(account_id)
    if not account:
        return None

    # Every member the swagger documents on this body that the record can
    # hold. `billingMode` and `usageType` were left out, so a change to
    # either was answered 200 and dropped. `state` is not documented here
    # and is kept: this mock's own expire/reactivate routes move it.
    updatable = ("name", "accountType", "expiration", "state", "billingMode", "usageType",
                 "externalId", "salesforceId", "unlimitedExpiration", "makeSocDefaultUi")
    for field in updatable:
        if field in data:
            setattr(account, field, data[field])
    account.updatedAt = utc_now()
    account_repo.save(account)
    return {"data": record_dict(account)}
