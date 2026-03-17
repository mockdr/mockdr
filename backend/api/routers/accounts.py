from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin
from api.dto.requests import AccountCreateBody, AccountUpdateBody
from application.accounts import commands as account_commands
from application.accounts import queries as account_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Accounts"])


@router.get("/accounts")
def list_accounts(
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a paginated list of all accounts."""
    return account_queries.list_accounts(cursor, limit)


@router.post("/accounts")
def create_account(body: AccountCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a new account.

    Body: ``{"data": {name, accountType?, expiration?}}``

    Returns:
        Dict with ``data`` containing the created account record.
    """
    return account_commands.create_account(body.data)


@router.get("/accounts/{account_id}")
def get_account(account_id: str) -> dict:
    """Return a single account by ID."""
    result = account_queries.get_account(account_id)
    if not result:
        raise HTTPException(status_code=404)
    return result


@router.put("/accounts/{account_id}")
def update_account(
    account_id: str,
    body: AccountUpdateBody,
    _: dict = Depends(require_admin),
) -> dict:
    """Update an existing account (partial update — only present fields are changed).

    Body: ``{"data": {name?, accountType?, expiration?, state?}}``

    Raises:
        HTTPException: 404 if the account is not found.
    """
    result = account_commands.update_account(account_id, body.data)
    if result is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return result
