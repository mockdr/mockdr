"""Write-side command handlers for Account CRUD.

POST /accounts      → create_account
PUT  /accounts/{id} → update_account
"""
from dataclasses import asdict

from domain.account import Account
from repository.account_repo import account_repo
from utils.dt import utc_now
from utils.id_gen import new_id


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
    )
    account_repo.save(account)
    return {"data": asdict(account)}


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

    updatable = ("name", "accountType", "expiration", "state")
    for field in updatable:
        if field in data:
            setattr(account, field, data[field])
    account.updatedAt = utc_now()
    account_repo.save(account)
    return {"data": asdict(account)}
