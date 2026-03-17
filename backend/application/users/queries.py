from dataclasses import asdict

from repository.user_repo import user_repo
from utils.filtering import FilterSpec, apply_filters
from utils.internal_fields import USER_INTERNAL_FIELDS
from utils.pagination import USER_CURSOR, build_list_response, paginate
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("accountIds", "accountId", "in"),
    FilterSpec("roles", "role", "in"),   # internal field, used for filtering only
    FilterSpec("email", "email", "contains"),
]


def list_users(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of users with internal fields stripped."""
    records = [asdict(u) for u in user_repo.list_all()]
    filtered = apply_filters(records, params, FILTER_SPECS)  # filter before strip
    page, next_cursor, total = paginate(filtered, cursor, limit, USER_CURSOR)
    stripped = [strip_fields(r, USER_INTERNAL_FIELDS) for r in page]
    return build_list_response(stripped, next_cursor, total)


def get_user(user_id: str) -> dict | None:
    """Return a single user by ID with internal fields stripped, or None."""
    user = user_repo.get(user_id)
    if not user:
        return None
    return {"data": strip_fields(asdict(user), USER_INTERNAL_FIELDS)}


def get_user_by_token(token: str) -> dict | None:
    """Return the user associated with the given API token, or None.

    Args:
        token: The raw API token string.

    Returns:
        Dict with ``data`` containing the user record, or None if not found.
    """
    record = user_repo.get_token_record(token)
    if not record:
        return None
    user = user_repo.get(record["userId"])
    if not user:
        return None
    return {"data": strip_fields(asdict(user), USER_INTERNAL_FIELDS)}
