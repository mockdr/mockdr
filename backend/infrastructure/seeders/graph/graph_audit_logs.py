"""Seed Microsoft Graph Directory Audit Logs with realistic admin activity."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.audit_log import GraphAuditLog
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.audit_log_repo import graph_audit_log_repo
from repository.graph.user_repo import graph_user_repo

# ---------------------------------------------------------------------------
# Activity / category mapping
# ---------------------------------------------------------------------------

_ACTIVITIES: list[tuple[str, str, str]] = [
    # (activityDisplayName, category, targetResourceType)
    ("Add user", "UserManagement", "User"),
    ("Update user", "UserManagement", "User"),
    ("Delete user", "UserManagement", "User"),
    ("Reset user password", "UserManagement", "User"),
    ("Add member to group", "GroupManagement", "Group"),
    ("Update conditional access policy", "PolicyManagement", "Policy"),
    ("Add application", "ApplicationManagement", "Application"),
    ("Consent to application", "ApplicationManagement", "Application"),
    ("Add service principal", "ApplicationManagement", "ServicePrincipal"),
    ("Update role assignment", "RoleManagement", "Role"),
]

_LOGGED_BY_SERVICES: dict[str, str] = {
    "UserManagement": "Core Directory",
    "GroupManagement": "Core Directory",
    "PolicyManagement": "Conditional Access",
    "ApplicationManagement": "Core Directory",
    "RoleManagement": "PIM",
}

_ENTRY_COUNT: int = 100


def seed_graph_audit_logs(fake: Faker, user_ids: list[str]) -> None:
    """Create 100 directory audit log entries over the last 30 days.

    Distributes activities across users and categories with a 90/10
    success/failure split.

    Args:
        fake:     Shared Faker instance (seeded externally).
        user_ids: List of Graph user ID strings to reference as initiators.
    """
    if not user_ids:
        return

    # Build user lookup
    user_details: dict[str, dict[str, str]] = {}
    for uid in user_ids:
        user = graph_user_repo.get(uid)
        if user is not None:
            user_details[uid] = {
                "id": uid,
                "displayName": user.displayName,
                "userPrincipalName": user.userPrincipalName,
            }
        else:
            user_details[uid] = {
                "id": uid,
                "displayName": "Unknown User",
                "userPrincipalName": "unknown@acmecorp.onmicrosoft.com",
            }

    for _ in range(_ENTRY_COUNT):
        activity_name, category, target_type = random.choice(_ACTIVITIES)
        initiator_uid = random.choice(user_ids)
        initiator = user_details[initiator_uid]

        # Result: 90% success, 10% failure
        result = "success" if random.random() < 0.90 else "failure"

        # Target resource
        target_resources = [
            {
                "id": graph_uuid(),
                "displayName": fake.name() if target_type == "User" else fake.bs().title(),
                "type": target_type,
            },
        ]

        logged_by = _LOGGED_BY_SERVICES.get(category, "Core Directory")

        graph_audit_log_repo.save(GraphAuditLog(
            id=graph_uuid(),
            category=category,
            correlationId=graph_uuid(),
            result=result,
            activityDisplayName=activity_name,
            activityDateTime=rand_ago(max_days=30),
            initiatedBy={
                "user": {
                    "id": initiator["id"],
                    "displayName": initiator["displayName"],
                    "userPrincipalName": initiator["userPrincipalName"],
                },
                "app": {},
            },
            targetResources=target_resources,
            loggedByService=logged_by,
        ))
