"""Exclusions seeder — seeds path/hash/certificate/browser exclusion records."""
import random

from faker import Faker

from domain.exclusion import Exclusion
from infrastructure.safe_net import doc_domain
from infrastructure.seeders._shared import rand_after, rand_ago
from repository.exclusion_repo import exclusion_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.user_repo import user_repo
from utils.id_gen import new_id

#: Applications an exclusion is written against, when it is written against
#: one rather than a path or a hash.
_APPLICATIONS: list[str] = [
    "Microsoft Teams", "Google Chrome", "Docker Desktop",
    "Visual Studio Code", "Slack", "Zoom",
]


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
    for i in range(15):
        eid = new_id()
        ex_type = random.choice(["path", "white_hash", "certificate", "browser"])
        value_map = {
            "path": fake.file_path(),
            "white_hash": fake.sha1(),
            "certificate": f"CN={fake.company()}",
            "browser": doc_domain(),
        }
        ex_site_id = random.choice(site_ids)
        site_obj = site_repo.get(ex_site_id)
        assert site_obj is not None

        # Tenant and site were the only two scopes here, so the documented
        # `accountIds` and `groupIds` filters could match no exclusion at
        # all. An exclusion can be written at any of the four levels.
        scope_obj: dict[str, object]
        # Round-robin rather than drawn: a scope that appears only on some
        # seeds gives a filter that passes only on some runs, which is the
        # flakiness this seed keeps being cleaned of.
        level = ["site", "account", "group", "tenant"][i % 4]
        if level == "tenant":
            scope_obj = {"tenant": True}
            scope_name = "Global"
            scope_path = "Global"
        elif level == "account":
            scope_obj = {"accountIds": [site_obj.accountId]}
            scope_name = site_obj.accountName
            scope_path = f"Global / {site_obj.accountName}"
        elif level == "group":
            group_ids = [g.id for g in group_repo.list_all() if g.siteId == ex_site_id]
            if group_ids:
                scope_obj = {"groupIds": [random.choice(group_ids)]}
                scope_name = site_obj.name
                scope_path = f"Global / Acme Corp Security / {site_obj.name}"
            else:
                scope_obj = {"siteId": ex_site_id}
                scope_name = site_obj.name
                scope_path = f"Global / Acme Corp Security / {site_obj.name}"
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
            createdAt=(created := rand_ago(60)),
            updatedAt=rand_after(created),
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
            # An exclusion written against a signed application names it.
            applicationName=(
                random.choice(_APPLICATIONS) if random.random() > 0.6 else None
            ),
            # internal
            siteId=ex_site_id,
        ))
