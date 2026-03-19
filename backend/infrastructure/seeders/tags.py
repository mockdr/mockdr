"""Tags seeder — creates scoped tag definitions across the hierarchy."""
from faker import Faker

from domain.tag import Tag
from infrastructure.seeders._shared import ago, rand_ago
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.tag_repo import tag_repo
from utils.id_gen import new_id

# (key, value, description)
_GLOBAL_TAGS = [
    ("Virtual", "Virtual", "Virtual machine endpoints"),
    ("Critical", "Critical", "Business-critical assets"),
    ("Production", "Production", "Production environment"),
]

_ACCOUNT_TAGS = [
    ("Compliance", "SOX", "SOX compliance scope"),
    ("Environment", "Corporate", "Corporate-managed endpoints"),
]

# Per-site tags: index 0 = Workstations, 1 = Servers, 2 = Cloud Infrastructure
_SITE_TAGS: list[list[tuple[str, str, str]]] = [
    [("Department", "Engineering", "Engineering workstations"),
     ("Department", "Finance", "Finance workstations")],
    [("Tier", "Tier-1", "Tier-1 production servers"),
     ("Tier", "Tier-2", "Tier-2 staging servers")],
    [("Region", "us-east-1", "AWS US-East region"),
     ("Region", "eu-west-1", "AWS EU-West region")],
]

# Group-level tags (applied to first few groups found)
_GROUP_TAGS = [
    ("Role", "Developer", "Developer machines"),
    ("Role", "SysAdmin", "System administrator machines"),
    ("Access", "VPN", "VPN-connected endpoints"),
    ("Access", "RemoteOnly", "Remote-only workers"),
]


def seed_tags(
    fake: Faker,
    account_id: str,
    account_name: str,
    site_ids: list[str],
    group_ids_by_site: dict[str, list[str]],
    creator_user_id: str = "",
) -> list[Tag]:
    """Create scoped tag definitions and persist them to the tag repository.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        account_id: ID of the parent account.
        account_name: Display name of the parent account.
        site_ids: List of site IDs from the sites seeder.
        group_ids_by_site: Mapping of site ID to list of group IDs.
        creator_user_id: ID of the admin user that "created" the tags.

    Returns:
        All created ``Tag`` objects (for use by the agent seeder).
    """
    created: list[Tag] = []
    creator = "admin@acmecorp.internal"

    def _make_tag(
        key: str, value: str, desc: str,
        scope_id: str, scope_level: str, scope_path: str,
        days_ago: int, update_window: int,
    ) -> Tag:
        return Tag(
            id=new_id(),
            key=key,
            value=value,
            type="agents",
            description=desc,
            scopeId=scope_id,
            scopeLevel=scope_level,
            scopePath=scope_path,
            createdAt=ago(days=days_ago),
            updatedAt=rand_ago(update_window),
            createdBy=creator,
            updatedBy=creator,
            createdById=creator_user_id,
            updatedById=creator_user_id,
        )

    # Global tags
    for key, value, desc in _GLOBAL_TAGS:
        tag = _make_tag(key, value, desc, "", "global", "Global", 200, 60)
        tag_repo.save(tag)
        created.append(tag)

    # Account tags
    for key, value, desc in _ACCOUNT_TAGS:
        tag = _make_tag(key, value, desc, account_id, "account", f"Global\\{account_name}", 180, 45)
        tag_repo.save(tag)
        created.append(tag)

    # Site tags
    for i, sid in enumerate(site_ids):
        site = site_repo.get(sid)
        if not site or i >= len(_SITE_TAGS):
            continue
        scope_path = f"Global\\{account_name}\\{site.name}"
        for key, value, desc in _SITE_TAGS[i]:
            tag = _make_tag(key, value, desc, sid, "site", scope_path, 150, 30)
            tag_repo.save(tag)
            created.append(tag)

    # Group tags — distribute across first groups found
    all_groups = []
    for sid in site_ids:
        for gid in group_ids_by_site.get(sid, []):
            group = group_repo.get(gid)
            if group:
                all_groups.append(group)

    for idx, (key, value, desc) in enumerate(_GROUP_TAGS):
        if idx >= len(all_groups):
            break
        group = all_groups[idx]
        site = site_repo.get(group.siteId)
        site_name = site.name if site else ""
        scope_path = f"Global\\{account_name}\\{site_name}\\{group.name}"
        tag = _make_tag(key, value, desc, group.id, "group", scope_path, 120, 20)
        tag_repo.save(tag)
        created.append(tag)

    return created
