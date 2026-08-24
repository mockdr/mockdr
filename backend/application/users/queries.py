
from application.documented_filters import DOCUMENTED_FILTERS
from repository.user_repo import user_repo
from utils.filtering import FilterSpec, apply_filters, apply_query_options
from utils.internal_fields import USER_INTERNAL_FIELDS
from utils.pagination import USER_CURSOR, build_list_response, paginate
from utils.s1_fixtures import complete_s1
from utils.serde import record_dict
from utils.strip import strip_fields

FILTER_SPECS = [
    FilterSpec("ids", "id", "in"),
    FilterSpec("accountIds", "accountId", "in"),
    FilterSpec("roles", "role", "in"),  # internal field, used for filtering only
    FilterSpec("email", "email", "contains"),
]


def list_users(params: dict, cursor: str | None, limit: int) -> dict:
    """Return a filtered, paginated list of users with internal fields stripped."""
    filtered = apply_filters(
        user_repo.list_all(),
        params,
        FILTER_SPECS + DOCUMENTED_FILTERS.get("/users", []),
    )  # filter before strip
    filtered = apply_query_options(filtered, params)
    page, next_cursor, total = paginate(filtered, cursor, limit, USER_CURSOR)
    stripped = [strip_fields(record_dict(u), USER_INTERNAL_FIELDS) for u in page]
    response = build_list_response(
        stripped, next_cursor, total, definition="users.schemas_GetUserListSchema_many_200"
    )
    # The token itself never leaves the server: apiToken is null in every response.
    for item in response["data"]:
        item["apiToken"] = None
    return response


def get_user(user_id: str) -> dict | None:
    """Return a single user by ID with internal fields stripped, or None."""
    user = user_repo.get(user_id)
    if not user:
        return None
    response = complete_s1(
        {"data": strip_fields(record_dict(user), USER_INTERNAL_FIELDS)},
        "users.schemas_SingleUserSchema_200",
    )
    # The token itself never leaves the server: apiToken is null in every
    # response, whatever the schema's object shape (critical test).
    response["data"]["apiToken"] = None
    return response


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
    return {"data": strip_fields(record_dict(user), USER_INTERNAL_FIELDS)}
