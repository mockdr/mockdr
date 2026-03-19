"""Seed Microsoft Graph Groups and their members."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.group import GraphGroup
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.group_repo import graph_group_repo
from repository.graph.user_repo import graph_user_repo
from repository.store import store


def _users_by_department(department: str) -> list[dict]:
    """Return [{id, displayName}] for all users in the given department."""
    return [
        {"id": u.id, "displayName": u.displayName}
        for u in graph_user_repo.list_all()
        if u.department == department
    ]


def _all_user_dicts() -> list[dict]:
    """Return [{id, displayName}] for every seeded user."""
    return [
        {"id": u.id, "displayName": u.displayName}
        for u in graph_user_repo.list_all()
    ]


def _random_subset(members: list[dict], min_count: int = 2) -> list[dict]:
    """Return a random subset of at least *min_count* members."""
    if len(members) <= min_count:
        return list(members)
    count = random.randint(min_count, len(members))
    return random.sample(members, count)


def seed_graph_groups(fake: Faker, user_ids: list[str]) -> None:  # noqa: ARG001 — user_ids kept for seeder interface consistency
    """Create 10 groups with realistic membership assignments."""
    all_users = _all_user_dicts()

    # ── Static group definitions ──────────────────────────────────────────
    groups: list[dict] = [
        {
            "displayName": "All Employees",
            "description": "All employees in the organisation.",
            "securityEnabled": True,
            "members": all_users,
        },
        {
            "displayName": "IT Department",
            "description": "IT department security group.",
            "securityEnabled": True,
            "members": _users_by_department("IT") or _random_subset(all_users),
        },
        {
            "displayName": "Finance",
            "description": "Finance department security group.",
            "securityEnabled": True,
            "members": _users_by_department("Finance") or _random_subset(all_users),
        },
        {
            "displayName": "Marketing",
            "description": "Marketing department security group.",
            "securityEnabled": True,
            "members": _users_by_department("Marketing") or _random_subset(all_users),
        },
        {
            "displayName": "Sales",
            "description": "Sales department security group.",
            "securityEnabled": True,
            "members": _users_by_department("Sales") or _random_subset(all_users),
        },
        {
            "displayName": "Executives",
            "description": "Executive leadership security group.",
            "securityEnabled": True,
            "members": _users_by_department("Executive") or _random_subset(all_users),
        },
        {
            "displayName": "Remote Workers",
            "description": "Microsoft 365 group for remote employees.",
            "groupTypes": ["Unified"],
            "securityEnabled": False,
            "mailEnabled": True,
            "visibility": "Private",
            "members": _random_subset(all_users, 3),
        },
        {
            "displayName": "Security Team",
            "description": "Security operations team.",
            "securityEnabled": True,
            "members": _random_subset(all_users, 2),
        },
        {
            "displayName": "MFA Required",
            "description": "Dynamic group: users with strong authentication methods.",
            "securityEnabled": True,
            "membershipRule": "user.strongAuthenticationMethods -ne null",
            "membershipRuleProcessingState": "On",
        },
        {
            "displayName": "Compliant Devices",
            "description": "Dynamic group: devices that are compliant.",
            "securityEnabled": True,
            "membershipRule": "device.complianceState -eq 'compliant'",
            "membershipRuleProcessingState": "On",
        },
    ]

    for spec in groups:
        group_id = graph_uuid()
        mail_nickname = spec["displayName"].lower().replace(" ", "-")

        group = GraphGroup(
            id=group_id,
            displayName=spec["displayName"],
            description=spec.get("description", ""),
            groupTypes=spec.get("groupTypes", []),
            securityEnabled=spec.get("securityEnabled", True),
            mailEnabled=spec.get("mailEnabled", False),
            mailNickname=mail_nickname,
            membershipRule=spec.get("membershipRule"),
            membershipRuleProcessingState=spec.get("membershipRuleProcessingState"),
            createdDateTime=rand_ago(max_days=365),
            visibility=spec.get("visibility", "Public"),
        )
        graph_group_repo.save(group)

        # Store members (dynamic groups have no static members)
        members = spec.get("members")
        if members is not None:
            store.save("graph_group_members", group_id, members)
        else:
            store.save("graph_group_members", group_id, [])
