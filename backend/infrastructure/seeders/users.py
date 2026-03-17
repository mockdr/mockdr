"""Users seeder — seeds the three preset users and their API tokens."""

from datetime import UTC, datetime, timedelta

from faker import Faker

from domain.user import User
from infrastructure.seeders._shared import ago, rand_ago
from repository.user_repo import user_repo
from utils.id_gen import new_id

_TOKEN_TTL_DAYS = 180


def _expires_at() -> str:
    return (datetime.now(UTC) + timedelta(days=_TOKEN_TTL_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Token value, role label, email, full name — order is deterministic
_TOKEN_CONFIGS: list[tuple[str, str, str, str]] = [
    ("admin-token-0000-0000-000000000001", "Admin",       "admin@acmecorp.com",  "Admin User"),
    ("viewer-token-0000-0000-000000000002", "Viewer",     "viewer@acmecorp.com", "Viewer User"),
    ("soc-analyst-token-000-000000000003",  "SOC Analyst", "soc@acmecorp.com",   "SOC Analyst"),
]


def seed_users(fake: Faker, account_id: str, account_name: str) -> list[str]:
    """Create the preset users and their API tokens, then persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        account_id: ID of the parent account.
        account_name: Display name of the parent account.

    Returns:
        List of user IDs in the same order as the token config.
    """
    user_ids: list[str] = []
    scope_role_id = new_id()

    for token_val, role, email, full_name in _TOKEN_CONFIGS:
        uid = new_id()
        user_ids.append(uid)
        role_id = new_id()
        user_repo.save(User(
            id=uid,
            email=email,
            fullName=full_name,
            source="mgmt",
            twoFaEnabled=True,
            twoFaConfigured=True,
            twoFaStatus="configured",
            twoFaEnabledReadOnly=False,
            primaryTwoFaMethod="application",
            dateJoined=ago(days=180),
            lastLogin=rand_ago(7),
            firstLogin=ago(days=180),
            scope="tenant",
            lowestRole=role,
            emailVerified=True,
            emailReadOnly=False,
            fullNameReadOnly=False,
            groupsReadOnly=False,
            canGenerateApiToken=True,
            isSystem=False,
            scopeRoles=[{
                "id": scope_role_id,
                "roleId": role_id,
                "roleName": role,
                "roles": [role],
                "name": account_name,
                "accountName": account_name,
            }],
            siteRoles=[],
            tenantRoles=[],
            apiToken=None,
            # internal
            role=role,
            accountId=account_id,
            accountName=account_name,
            _apiToken=token_val,
        ))
        user_repo.save_token(token_val, {
            "token": token_val,
            "userId": uid,
            "role": role,
            "email": email,
            "fullName": full_name,
            "accountId": account_id,
            "expiresAt": _expires_at(),
        })

    return user_ids
