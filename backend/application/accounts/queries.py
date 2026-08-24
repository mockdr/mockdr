
from application.documented_filters import DOCUMENTED_FILTERS
from repository.account_repo import account_repo
from utils.filtering import FilterSpec, apply_filters
from utils.pagination import ACCOUNT_CURSOR, build_list_response, build_single_response, paginate
from utils.s1_fixtures import restrict_s1
from utils.serde import record_dict

#: The swagger's own filters for GET /accounts.
FILTER_SPECS = [
    FilterSpec("accountIds", "id", "in"),
    FilterSpec("name", "name", "contains"),
    FilterSpec("states", "state", "in", enum=True),
    FilterSpec("accountType", "accountType", "in", enum=True),
    FilterSpec("updatedAt", "updatedAt", "eq"),
]


def list_accounts(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a paginated list of accounts, narrowed by the request's filters."""
    records = apply_filters(
        [record_dict(a) for a in account_repo.list_all()],
        params,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/accounts", []),
    )
    page, next_cursor, total = paginate(records, cursor, limit, ACCOUNT_CURSOR)
    return build_list_response(
        page,
        next_cursor,
        total,
        definition="accounts.schemas_AccountViewSchema_many_200",
        strict=True,
    )


def get_account(account_id: str) -> dict | None:
    """Return a single account by ID, or None if not found."""
    account = account_repo.get(account_id)
    return (
        restrict_s1(
            build_single_response(record_dict(account)), "accounts.schemas_AccountViewSchema_200"
        )
        if account
        else None
    )
