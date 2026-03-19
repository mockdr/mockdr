"""Seed Microsoft Graph mail inbox rules."""
from __future__ import annotations

from faker import Faker

from domain.graph.mail_rule import GraphMailRule
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.mail_rule_repo import graph_mail_rule_repo


def seed_graph_mail_rules(fake: Faker, user_ids: list[str]) -> None:
    """Create mail rules across multiple users.

    Includes external forwarding rules (forwardTo, redirectTo,
    forwardAsAttachmentTo) for realistic email forwarding detection.

    Deliberately places forwarding rules on disabled (former employee)
    accounts to simulate common compliance violations:
    - Former employee still forwarding company mail to personal Gmail
    - Disabled account silently redirecting HR correspondence externally
    - Auto-forward-all rule created before offboarding, never cleaned up
    """
    from repository.graph.user_repo import graph_user_repo

    # Find the first disabled user to attach forwarding rules to
    disabled_ids = [
        uid for uid in user_ids
        if (u := graph_user_repo.get(uid)) and not u.accountEnabled
    ]
    # Find the first enabled user for the benign rule + one suspicious enabled rule
    enabled_ids = [
        uid for uid in user_ids
        if (u := graph_user_repo.get(uid)) and u.accountEnabled
    ]

    # Target: disabled user gets the most dangerous forwarding rules
    former_employee = disabled_ids[0] if disabled_ids else user_ids[1]
    active_user = enabled_ids[0] if enabled_ids else user_ids[0]
    benign_user = enabled_ids[1] if len(enabled_ids) > 1 else user_ids[2]

    rules: list[GraphMailRule] = [
        # Active employee — forwards invoices to personal Gmail (policy violation)
        GraphMailRule(
            id=graph_uuid(),
            displayName="Forward invoices",
            sequence=1,
            isEnabled=True,
            conditions={
                "subjectContains": ["invoice", "payment"],
            },
            actions={
                "forwardTo": [
                    {
                        "emailAddress": {
                            "name": "Personal",
                            "address": "user0.personal@gmail.com",
                        },
                    },
                ],
                "stopProcessingRules": True,
            },
            _user_id=active_user,
        ),
        # FORMER EMPLOYEE — redirects HR mail to external consulting firm
        # Account disabled but forwarding rule still active (offboarding gap)
        GraphMailRule(
            id=graph_uuid(),
            displayName="Redirect HR",
            sequence=1,
            isEnabled=True,
            conditions={
                "sentFrom": {
                    "emailAddresses": [
                        {"address": "hr@acmecorp.onmicrosoft.com"},
                    ],
                },
            },
            actions={
                "redirectTo": [
                    {
                        "emailAddress": {
                            "name": "External HR",
                            "address": "hr@external-consulting.com",
                        },
                    },
                ],
                "stopProcessingRules": False,
            },
            _user_id=former_employee,
        ),
        # FORMER EMPLOYEE — auto-forwards EVERYTHING to competitor domain
        # Created before offboarding, never discovered or cleaned up
        GraphMailRule(
            id=graph_uuid(),
            displayName="Auto-forward all",
            sequence=2,
            isEnabled=True,
            conditions={},
            actions={
                "forwardAsAttachmentTo": [
                    {
                        "emailAddress": {
                            "name": "Archive",
                            "address": "archive@competitor.com",
                        },
                    },
                ],
                "stopProcessingRules": False,
            },
            _user_id=former_employee,
        ),
        # Active employee — benign rule, moves newsletters to Archive folder
        GraphMailRule(
            id=graph_uuid(),
            displayName="Move newsletters",
            sequence=1,
            isEnabled=True,
            conditions={
                "subjectContains": ["newsletter", "digest"],
            },
            actions={
                "moveToFolder": "Archive",
                "stopProcessingRules": False,
            },
            _user_id=benign_user,
        ),
    ]

    for rule in rules:
        graph_mail_rule_repo.save(rule)
