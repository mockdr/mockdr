"""Seed Microsoft Graph Directory Roles and their members."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.directory_role import GraphDirectoryRole
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.directory_role_repo import graph_directory_role_repo
from repository.store import store

# ---------------------------------------------------------------------------
# Built-in directory role definitions
# ---------------------------------------------------------------------------

_ROLES: list[dict[str, str]] = [
    {
        "displayName": "Global Administrator",
        "description": "Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities.",
        "roleTemplateId": "62e90394-69f5-4237-9190-012177145e10",
    },
    {
        "displayName": "Security Administrator",
        "description": "Can read security information and reports, and manage configuration in Azure AD and Office 365.",
        "roleTemplateId": "194ae4cb-b126-40b2-bd5b-6091b380977d",
    },
    {
        "displayName": "Security Reader",
        "description": "Can read security information and reports in Azure AD and Office 365.",
        "roleTemplateId": "5d6b6bb7-de71-4623-b4af-96380a352509",
    },
    {
        "displayName": "Intune Administrator",
        "description": "Can manage all aspects of the Intune product.",
        "roleTemplateId": "3a2c62db-5318-420d-8d74-23affee5d9d5",
    },
    {
        "displayName": "User Administrator",
        "description": "Can manage all aspects of users and groups, including resetting passwords for limited admins.",
        "roleTemplateId": "fe930be7-5e62-47db-91af-98c3a49a38b1",
    },
    {
        "displayName": "Conditional Access Administrator",
        "description": "Can manage Conditional Access capabilities.",
        "roleTemplateId": "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
    },
    {
        "displayName": "Exchange Administrator",
        "description": "Can manage all aspects of the Exchange product.",
        "roleTemplateId": "29232cdf-9323-42fd-ade2-1d097af3e4de",
    },
    {
        "displayName": "Teams Administrator",
        "description": "Can manage the Microsoft Teams service.",
        "roleTemplateId": "69091246-20e8-4a56-aa4d-066075b2a7a8",
    },
]


def seed_graph_directory_roles(fake: Faker, user_ids: list[str]) -> None:
    """Create directory roles and assign members.

    Deliberately seeds compliance violations:
    - Global Administrator has 5 members (CIS recommends 2-4)
    - Disabled (former employee) users remain in privileged roles
    - Some admins may lack MFA (checked via registration details)
    """
    from repository.graph.user_repo import graph_user_repo

    # Separate enabled and disabled users for targeted assignment
    disabled_ids = [
        uid for uid in user_ids
        if (u := graph_user_repo.get(uid)) and not u.accountEnabled
    ]
    enabled_ids = [
        uid for uid in user_ids
        if (u := graph_user_repo.get(uid)) and u.accountEnabled
    ]

    for spec in _ROLES:
        role_id = graph_uuid()
        role = GraphDirectoryRole(
            id=role_id,
            displayName=spec["displayName"],
            description=spec["description"],
            roleTemplateId=spec["roleTemplateId"],
        )
        graph_directory_role_repo.save(role)

        if spec["displayName"] == "Global Administrator":
            # CIS violation: too many Global Admins (5, recommended max 4)
            # Include 1 disabled user (former employee with GA role not revoked)
            ga_enabled = random.sample(enabled_ids, min(4, len(enabled_ids)))
            ga_disabled = disabled_ids[:1] if disabled_ids else []
            members = ga_enabled + ga_disabled
        elif spec["displayName"] in ("Security Administrator", "Security Reader",
                                      "Intune Administrator", "Conditional Access Administrator"):
            # Include a disabled user in some privileged roles
            member_count = random.randint(2, 3)
            members = random.sample(enabled_ids, min(member_count, len(enabled_ids)))
            if disabled_ids and random.random() < 0.5:
                members.append(random.choice(disabled_ids))
        else:
            # Standard: 1-3 enabled members
            member_count = random.randint(1, min(3, len(enabled_ids)))
            members = random.sample(enabled_ids, member_count)

        store.save("graph_directory_role_members", role_id, members)
