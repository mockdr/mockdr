"""CrowdStrike host groups seeder — creates groups and assigns hosts."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_host_group import CsHostGroup
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import cs_hex_id
from repository.cs_host_group_repo import cs_host_group_repo
from repository.cs_host_repo import cs_host_repo

_GROUP_DEFS: list[dict[str, str]] = [
    {
        "name": "Windows Workstations",
        "description": "All Windows workstation endpoints",
        "group_type": "dynamic",
        "assignment_rule": "platform_name:'Windows'+product_type_desc:'Workstation'",
    },
    {
        "name": "Linux Servers",
        "description": "All Linux server endpoints",
        "group_type": "dynamic",
        "assignment_rule": "platform_name:'Linux'+product_type_desc:'Server'",
    },
    {
        "name": "Mac Endpoints",
        "description": "All macOS managed endpoints",
        "group_type": "dynamic",
        "assignment_rule": "platform_name:'Mac'",
    },
    {
        "name": "Critical Assets",
        "description": "Manually curated critical infrastructure hosts",
        "group_type": "static",
        "assignment_rule": "",
    },
    {
        "name": "Staging Environment",
        "description": "Hosts in the staging/pre-production environment",
        "group_type": "static",
        "assignment_rule": "",
    },
]

_CREATOR: str = "cs-mock-admin-client"


def _host_matches_rule(host_platform: str, host_product_type: str, rule: str) -> bool:
    """Check whether a host matches a dynamic group assignment rule.

    Supports simple CrowdStrike FQL-style rules with ``+`` (AND) and
    ``field:'value'`` syntax.

    Args:
        host_platform: The host's ``platform_name`` value.
        host_product_type: The host's ``product_type_desc`` value.
        rule: The assignment rule string.

    Returns:
        True if the host satisfies all conditions in the rule.
    """
    if not rule:
        return False

    conditions = rule.split("+")
    for condition in conditions:
        field, _, value = condition.partition(":")
        value = value.strip("'\"")
        field = field.strip()
        if field == "platform_name" and host_platform != value:
            return False
        if field == "product_type_desc" and host_product_type != value:
            return False
    return True


def seed_cs_host_groups(fake: Faker, host_ids: list[str]) -> list[str]:
    """Create CrowdStrike host groups and assign hosts to them.

    Creates five groups (three dynamic, two static). Dynamic groups use
    rule-based assignment; static groups receive a random subset of hosts.
    After creation, each host's ``groups`` field is updated with its
    applicable group IDs.

    Args:
        fake: Shared Faker instance (seeded externally).
        host_ids: List of CS ``device_id`` strings.

    Returns:
        List of host group ID strings.
    """
    all_hosts = cs_host_repo.list_all()
    host_lookup = {h.device_id: h for h in all_hosts}
    group_ids: list[str] = []

    # Track which groups each host belongs to
    host_groups_map: dict[str, list[str]] = {hid: [] for hid in host_ids}

    created_ts = rand_ago(90)

    for group_def in _GROUP_DEFS:
        group_id = cs_hex_id()
        group_ids.append(group_id)

        cs_host_group_repo.save(CsHostGroup(
            id=group_id,
            name=group_def["name"],
            description=group_def["description"],
            group_type=group_def["group_type"],
            assignment_rule=group_def["assignment_rule"],
            created_by=_CREATOR,
            created_timestamp=created_ts,
            modified_by=_CREATOR,
            modified_timestamp=rand_ago(10),
        ))

        # Assign hosts to this group
        if group_def["group_type"] == "dynamic":
            rule = group_def["assignment_rule"]
            for hid in host_ids:
                host = host_lookup.get(hid)
                if host is not None and _host_matches_rule(
                    host.platform_name, host.product_type_desc, rule,
                ):
                    host_groups_map[hid].append(group_id)
        elif group_def["name"] == "Critical Assets":
            # Assign ~10 random hosts
            count = min(10, len(host_ids))
            for hid in random.sample(host_ids, count):
                host_groups_map[hid].append(group_id)
        elif group_def["name"] == "Staging Environment":
            # Assign ~8 random hosts
            count = min(8, len(host_ids))
            for hid in random.sample(host_ids, count):
                host_groups_map[hid].append(group_id)

    # Update each host's groups field
    for hid, gids in host_groups_map.items():
        if gids:
            host = host_lookup.get(hid)
            if host is not None:
                host.groups = gids
                cs_host_repo.save(host)

    return group_ids
