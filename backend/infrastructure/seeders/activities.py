"""Activities seeder — seeds 120 activity log entries spread across 90 days."""
import random
import uuid

from faker import Faker

from infrastructure.seeders._shared import ACTIVITY_CATALOG, rand_ago
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo


def seed_activities(
    fake: Faker,
    account_id: str,
    account_name: str,
    agent_ids: list[str],
    site_ids: list[str],
    group_ids_by_site: dict[str, list[str]],
    user_ids: list[str],
) -> None:
    """Create 120 activity log records and persist them.

    Entries are back-dated across the last 90 days to simulate a realistic
    audit trail.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        account_id: ID of the parent account.
        account_name: Display name of the parent account.
        agent_ids: Pool of agent IDs for random association (``None`` allowed).
        site_ids: Pool of site IDs.
        group_ids_by_site: Mapping of ``site_id → [group_id, ...]``.
        user_ids: Pool of user IDs for actor attribution.
    """
    for _ in range(120):
        act_type, act_desc = random.choice(ACTIVITY_CATALOG)
        act_sid = random.choice(site_ids)
        act_site = site_repo.get(act_sid)
        # Select a group from the same site so the pair is consistent
        site_groups = group_ids_by_site.get(act_sid, [])
        act_gid = random.choice(site_groups) if site_groups else ""
        act_group = group_repo.get(act_gid) if act_gid else None
        act_agent_id = random.choice(agent_ids + [None])
        act_agent = agent_repo.get(act_agent_id) if act_agent_id else None

        activity = activity_repo.create(
            activity_type=act_type,
            description=act_desc,
            agent_id=act_agent_id,
            user_id=random.choice(user_ids),
            site_id=act_sid,
        )
        activity.activityUuid = str(uuid.uuid4())
        activity.siteName = act_site.name if act_site else None
        activity.groupId = act_gid
        activity.groupName = act_group.name if act_group else None
        activity.accountId = account_id
        activity.accountName = account_name
        activity.primaryDescription = act_desc

        scope_name = (
            act_group.name if act_group
            else (act_site.name if act_site else "Global")
        )
        scope_level = (
            "Group" if act_group
            else ("Site" if act_site else "Account")
        )
        activity.data = {
            "accountName": account_name,
            "computerName": act_agent.computerName if act_agent else None,
            "groupName": act_group.name if act_group else None,
            "siteName": act_site.name if act_site else None,
            "fullScopeDetails": (
                f"Group {act_group.name if act_group else '—'} "
                f"in Site {act_site.name if act_site else '—'} "
                f"of Account {account_name}"
            ),
            "fullScopeDetailsPath": (
                f"Global / {account_name} / {act_site.name if act_site else '—'}"
                + (f" / {act_group.name}" if act_group else "")
            ),
            "assetType": None,
            "assetVersionsList": None,
            "externalServiceId": None,
            "ipAddress": act_agent.externalIp if act_agent else None,
            "realUser": None,
            "reasons": "",
            "scopeLevel": scope_level,
            "scopeName": scope_name,
            "sourceType": "API",
        }
        # Back-date to spread entries across 90 days
        activity.createdAt = rand_ago(90)
        activity.updatedAt = activity.createdAt
