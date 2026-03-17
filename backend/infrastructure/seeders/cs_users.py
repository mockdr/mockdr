"""CrowdStrike users seeder — creates mock Falcon console user accounts."""
from __future__ import annotations

from faker import Faker

from domain.cs_user import CsUser
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import CS_CID
from repository.cs_user_repo import cs_user_repo

_ROLES: list[list[str]] = [
    ["falcon_admin"],
    ["falcon_analyst"],
    ["falcon_analyst", "custom_ioc_manager"],
    ["falcon_viewer"],
    ["falcon_admin", "falcon_analyst"],
]


def seed_cs_users(fake: Faker) -> list[str]:
    """Create mock CrowdStrike user accounts.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of user UUIDs.
    """
    user_ids: list[str] = []

    for i in range(8):
        user_uuid = fake.uuid4()
        user_ids.append(user_uuid)

        first = fake.first_name()
        last = fake.last_name()
        email = f"{first.lower()}.{last.lower()}@acmecorp.internal"

        cs_user_repo.save(CsUser(
            uuid=user_uuid,
            cid=CS_CID,
            uid=email,
            first_name=first,
            last_name=last,
            customer="AcmeCorp",
            roles=_ROLES[i % len(_ROLES)],
            created_at=rand_ago(180),
            last_login_at=rand_ago(2),
            status="active",
        ))

    return user_ids
