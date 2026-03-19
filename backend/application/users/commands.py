import secrets
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from domain.user import User
from repository.account_repo import account_repo
from repository.store import store
from repository.user_repo import user_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import USER_INTERNAL_FIELDS
from utils.strip import strip_fields

_TOKEN_TTL_DAYS = 180


def _expires_at() -> str:
    return (datetime.now(UTC) + timedelta(days=_TOKEN_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_token() -> str:
    return secrets.token_hex(32)


def _delete_token(raw_token: str) -> None:
    """Remove a token from the api_tokens store."""
    if raw_token:
        store.delete("api_tokens", raw_token)


def create_user(data: dict) -> dict:
    """Create a new user and an initial API token.

    Returns:
        Dict with ``data`` containing the new user; ``data.apiToken`` holds
        the generated token (only exposed at creation time).
    """
    uid = new_id()
    role_id = new_id()
    scope_role_id = new_id()
    role = data.get("role", "Viewer")
    scope = data.get("scope", "tenant")
    now = utc_now()
    token = _make_token()

    # Derive account from the store (single-tenant mock)
    accounts = account_repo.list_all()
    acct = accounts[0] if accounts else None
    acct_id = acct.id if acct else ""
    acct_name = acct.name if acct else "Acme Corp Security"

    user = User(
        id=uid,
        email=data.get("email", ""),
        fullName=data.get("fullName", ""),
        source="mgmt",
        twoFaEnabled=data.get("twoFaEnabled", False),
        twoFaConfigured=False,
        twoFaStatus="not_configured",
        twoFaEnabledReadOnly=False,
        primaryTwoFaMethod="application",
        dateJoined=now,
        lastLogin=now,
        firstLogin=None,
        scope=scope,
        lowestRole=role,
        emailVerified=True,
        emailReadOnly=False,
        fullNameReadOnly=False,
        groupsReadOnly=False,
        canGenerateApiToken=True,
        isSystem=False,
        scopeRoles=data.get("scopeRoles", [
            {"id": scope_role_id, "roleId": role_id, "roleName": role, "roles": [role]}
        ]),
        siteRoles=[],
        tenantRoles=[],
        apiToken=None,
        role=role,
        accountId=acct_id,
        accountName=acct_name,
        _apiToken=token,
    )
    user_repo.save(user)
    user_repo.save_token(token, {
        "token": token, "userId": uid, "role": role,
        "email": user.email, "fullName": user.fullName, "accountId": acct_id,
        "expiresAt": _expires_at(),
    })

    result = strip_fields(asdict(user), USER_INTERNAL_FIELDS)
    result["apiToken"] = token   # expose only at creation time
    return {"data": result}


def update_user(user_id: str, data: dict) -> dict | None:
    """Partially update a user.

    Returns:
        Dict with ``data`` containing the updated user, or None if not found.
    """
    user = user_repo.get(user_id)
    if not user:
        return None
    if "fullName" in data:
        user.fullName = data["fullName"]
    if "email" in data:
        user.email = data["email"]
    if "scope" in data:
        user.scope = data["scope"]
    if "twoFaEnabled" in data:
        user.twoFaEnabled = data["twoFaEnabled"]
    if "role" in data:
        user.role = data["role"]
        user.lowestRole = data["role"]
    user_repo.save(user)
    return {"data": strip_fields(asdict(user), USER_INTERNAL_FIELDS)}


def delete_user(user_id: str) -> dict:
    """Delete a user and their API token.

    Returns:
        Dict with ``data.affected`` (1 if deleted, 0 if not found).
    """
    user = user_repo.get(user_id)
    if not user:
        return {"data": {"affected": 0}}
    _delete_token(user._apiToken)
    deleted = user_repo.delete(user_id)
    return {"data": {"affected": 1 if deleted else 0}}


def bulk_delete_users(ids: list[str]) -> dict:
    """Delete multiple users by ID.

    Returns:
        Dict with ``data.affected`` count.
    """
    affected = sum(1 for uid in ids if delete_user(uid)["data"]["affected"])
    return {"data": {"affected": affected}}


def generate_api_token(user_id: str) -> dict | None:
    """Revoke the existing token and issue a new one for the given user.

    Returns:
        Dict with ``data.{token, expiresAt}``, or None if user not found.
    """
    user = user_repo.get(user_id)
    if not user:
        return None
    _delete_token(user._apiToken)
    new_token = _make_token()
    exp = _expires_at()
    user._apiToken = new_token
    user_repo.save(user)
    user_repo.save_token(new_token, {
        "token": new_token, "userId": user_id, "role": user.role,
        "email": user.email, "fullName": user.fullName, "accountId": user.accountId,
        "expiresAt": exp,
    })
    return {"data": {"token": new_token, "expiresAt": exp}}


def get_api_token_details(user_id: str) -> dict | None:
    """Return token metadata for the given user.

    Returns:
        Dict with ``data`` containing token details, or None if not found.
    """
    user = user_repo.get(user_id)
    if not user or not user._apiToken:
        return None
    record = user_repo.get_token_record(user._apiToken)
    if not record:
        return None
    return {"data": {
        "id": user_id,
        "userId": user_id,
        "token": user._apiToken,
        "expiresAt": record.get("expiresAt"),
        "createdAt": user.dateJoined,
        "updatedAt": user.dateJoined,
    }}
