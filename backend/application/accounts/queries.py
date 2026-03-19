from dataclasses import asdict

from repository.account_repo import account_repo
from utils.pagination import ACCOUNT_CURSOR, build_list_response, build_single_response, paginate


def list_accounts(cursor: str | None, limit: int) -> dict:
    """Return a paginated list of all accounts."""
    records = [asdict(a) for a in account_repo.list_all()]
    page, next_cursor, total = paginate(records, cursor, limit, ACCOUNT_CURSOR)
    return build_list_response(page, next_cursor, total)


def get_account(account_id: str) -> dict | None:
    """Return a single account by ID, or None if not found."""
    account = account_repo.get(account_id)
    return build_single_response(asdict(account)) if account else None
