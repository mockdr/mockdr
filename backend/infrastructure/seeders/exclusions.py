"""Exclusions seeder — seeds path/hash/certificate/browser exclusion records."""
import random

from faker import Faker

from domain.exclusion import Exclusion
from infrastructure.seeders._shared import rand_ago
from repository.exclusion_repo import exclusion_repo
from repository.site_repo import site_repo
from repository.user_repo import user_repo
from utils.id_gen import new_id


def seed_exclusions(
    fake: Faker,
    site_ids: list[str],
    user_ids: list[str],
) -> None:
    """Create 15 exclusion records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        site_ids: Pool of site IDs for scope assignment.
        user_ids: Pool of user IDs for creator attribution.
    """
    for _ in range(15):
        eid = new_id()
        ex_type = random.choice(["path", "white_hash", "certificate", "browser"])
        value_map = {
            "path": fake.file_path(),
            "white_hash": fake.sha1(),
            "certificate": f"CN={fake.company()}",
            "browser": fake.domain_name(),
        }
        is_global = random.random() > 0.4
        ex_site_id = random.choice(site_ids)
        site_obj = site_repo.get(ex_site_id)
        assert site_obj is not None

        scope_obj: dict[str, str | bool]
        if is_global:
            scope_obj = {"tenant": True}
            scope_name = "Global"
            scope_path = "Global"
        else:
            scope_obj = {"siteId": ex_site_id}
            scope_name = site_obj.name
            scope_path = f"Global / Acme Corp Security / {site_obj.name}"

        uid = random.choice(user_ids)
        user_obj = user_repo.get(uid)
        exclusion_repo.save(Exclusion(
            id=eid,
            type=ex_type,
            value=value_map[ex_type],
            description=fake.sentence(nb_words=6),
            osType=random.choice(["windows", "macos", "linux", "windows_legacy"]),
            createdAt=rand_ago(60),
            updatedAt=rand_ago(10),
            userId=uid,
            userName=(
                f"{user_obj.fullName} ({user_obj.email})"
                if user_obj else "Unknown"
            ),
            mode=random.choice([
                "disable_all_monitors", "suppress", "disable_in_process_monitor",
            ]),
            source=random.choice(["user", "cloud"]),
            scope=scope_obj,
            scopeName=scope_name,
            scopePath=scope_path,
            actions=random.sample(["upload", "detect"], k=random.randint(1, 2)),
            pathExclusionType="file" if ex_type == "path" else None,
            notRecommended="NONE",
            imported=False,
            inAppInventory=False,
            includeChildren=random.choice([True, False]),
            includeParents=False,
            applicationName=None,
            # internal
            siteId=ex_site_id,
        ))
