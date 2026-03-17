"""Blocklist seeder — seeds hash-based blocklist (restriction) entries."""
import random

from faker import Faker

from infrastructure.seeders._shared import MALWARE_NAMES, rand_ago
from repository.blocklist_repo import blocklist_repo
from repository.site_repo import site_repo
from repository.user_repo import user_repo
from utils.id_gen import new_id


def seed_blocklist(
    fake: Faker,
    site_ids: list[str],
    user_ids: list[str],
) -> None:
    """Create 10 blocklist records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        site_ids: Pool of site IDs for scope assignment.
        user_ids: Pool of user IDs for creator attribution.
    """
    for _ in range(10):
        bid = new_id()
        bl_site_id = random.choice(site_ids)
        bl_site = site_repo.get(bl_site_id)
        bl_uid = random.choice(user_ids)
        bl_user = user_repo.get(bl_uid)
        bl_val = random.choice([fake.sha1(), fake.sha256()])
        blocklist_repo.save_raw(bid, {
            "id": bid,
            "value": bl_val,
            "sha256Value": bl_val if len(bl_val) == 64 else fake.sha256(),
            "type": "black_hash",
            "description": f"Blocked: {random.choice(MALWARE_NAMES)}",
            "source": random.choice(["user", "cloud", "action_from_threat"]),
            "osType": random.choice(["windows", "macos", "linux"]),
            "scope": {"siteIds": [bl_site_id], "groupIds": [], "accountIds": [], "tenant": False},
            "scopeName": bl_site.name if bl_site else "",
            "scopePath": (
                f"Global / Acme Corp Security / {bl_site.name}"
                if bl_site else ""
            ),
            "userId": bl_uid,
            "userName": (
                f"{bl_user.fullName} ({bl_user.email})"
                if bl_user else "Unknown"
            ),
            "imported": False,
            "includeChildren": random.choice([True, False]),
            "includeParents": False,
            "notRecommended": False,
            "createdAt": rand_ago(60),
            "updatedAt": rand_ago(10),
            # internal
            "siteId": bl_site_id,
        })
