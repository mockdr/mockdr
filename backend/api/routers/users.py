from fastapi import APIRouter, Depends, HTTPException, Query

from api.auth import require_admin, require_auth
from api.dto.requests import UserBulkDeleteBody, UserCreateBody, UserUpdateBody
from application.users import commands as user_commands
from application.users import queries as user_queries
from config import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

router = APIRouter(tags=["Users"])


@router.get("/users")
def list_users(
    ids: str = Query(None),
    roles: str = Query(None),
    email: str = Query(None),
    cursor: str = Query(None),
    limit: int = Query(DEFAULT_PAGE_SIZE, le=MAX_PAGE_SIZE),
) -> dict:
    """Return a filtered, paginated list of management console users."""
    params = {k: v for k, v in locals().items() if v is not None and k not in ("cursor", "limit")}
    return user_queries.list_users(params, cursor, limit)


@router.get("/users/login/by-token")
def login_by_token(current_user: dict = Depends(require_auth)) -> dict:
    """Return the currently authenticated user's profile."""
    result = user_queries.get_user_by_token(current_user.get("token", ""))
    if not result:
        raise HTTPException(status_code=401)
    return result


@router.post("/users")
def create_user(body: UserCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a new user.

    Body: ``{"data": {"email", "fullName", "scope", "role", ...}}``

    The generated API token is included in the response ``data.apiToken``
    (only returned at creation time, matching real S1 behaviour).
    """
    return user_commands.create_user(body.data)


@router.post("/users/delete-users")
def bulk_delete_users(body: UserBulkDeleteBody, _: dict = Depends(require_admin)) -> dict:
    """Bulk-delete users matching the filter.

    Body: ``{"filter": {"ids": [...]}}``
    """
    ids = body.filter.get("ids", [])
    return user_commands.bulk_delete_users(ids)


@router.post("/users/generate-api-token")
def generate_api_token(current_user: dict = Depends(require_auth)) -> dict:
    """Revoke and regenerate the API token for the currently authenticated user."""
    result = user_commands.generate_api_token(current_user.get("userId", ""))
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@router.get("/users/{user_id}")
def get_user(user_id: str, _: dict = Depends(require_auth)) -> dict:
    """Return a single user by ID."""
    result = user_queries.get_user(user_id)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@router.put("/users/{user_id}")
def update_user(user_id: str, body: UserUpdateBody, _: dict = Depends(require_admin)) -> dict:
    """Partially update a user.

    Body: ``{"data": {"fullName"?, "email"?, "scope"?, "role"?, "twoFaEnabled"?}}``
    """
    result = user_commands.update_user(user_id, body.data)
    if result is None:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@router.delete("/users/{user_id}")
def delete_user(user_id: str, _: dict = Depends(require_admin)) -> dict:
    """Delete a user by ID."""
    return user_commands.delete_user(user_id)


@router.get("/users/{user_id}/api-token-details")
def get_api_token_details(user_id: str, _: dict = Depends(require_auth)) -> dict:
    """Return API token metadata for the given user."""
    result = user_commands.get_api_token_details(user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Token not found")
    return result
