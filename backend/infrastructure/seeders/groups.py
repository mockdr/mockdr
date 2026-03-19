"""Groups seeder — seeds a sample of groups per site and their default policies."""
import random
import uuid

from faker import Faker

from domain.group import Group
from infrastructure.seeders._shared import ago, make_policy, rand_ago
from repository.group_repo import group_repo
from repository.policy_repo import policy_repo
from repository.site_repo import site_repo
from utils.id_gen import new_id

_GROUP_NAMES: list[str] = [
    "Default group", "Servers", "Workstations", "Contractors", "Executives",
]


def seed_groups(
    fake: Faker,
    account_id: str,
    account_name: str,
    site_ids: list[str],
) -> dict[str, list[str]]:
    """Create three groups per site and attach a default policy to each.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        account_id: ID of the parent account.
        account_name: Display name of the parent account.
        site_ids: List of site IDs to create groups under.

    Returns:
        Mapping of ``site_id → [group_id, ...]``.
    """
    group_ids_by_site: dict[str, list[str]] = {}

    for sid in site_ids:
        site = site_repo.get(sid)
        assert site is not None
        gids: list[str] = []
        for gname in random.sample(_GROUP_NAMES, 3):
            gid = new_id()
            gids.append(gid)
            group_repo.save(Group(
                id=gid,
                name=gname,
                siteId=sid,
                type="static",
                createdAt=ago(days=290),
                updatedAt=rand_ago(30),
                totalAgents=0,
                rank=None,
                isDefault=(gname == "Default group"),
                inherits=True,
                description=fake.sentence(nb_words=6),
                filterId=None,
                filterName=None,
                registrationToken=str(uuid.uuid4()),
                creator=None,
                creatorId=None,
                # internal
                siteName=site.name,
                accountId=account_id,
                accountName=account_name,
            ))
            policy_repo.save_for_group(gid, make_policy(gid, "group"))
        group_ids_by_site[sid] = gids

    return group_ids_by_site
