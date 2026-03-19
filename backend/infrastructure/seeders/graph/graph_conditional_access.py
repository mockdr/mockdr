"""Seed Microsoft Graph Conditional Access policies.

Covers common enterprise security baselines: MFA enforcement, legacy auth
blocking, compliant device requirements, and risk-based policies.
"""
from __future__ import annotations

from faker import Faker

from domain.graph.conditional_access_policy import GraphConditionalAccessPolicy
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.conditional_access_policy_repo import graph_ca_policy_repo
from utils.dt import utc_now


def seed_graph_conditional_access(fake: Faker) -> None:
    """Create six Conditional Access policies for the mock tenant."""
    now = utc_now()

    policies = [
        GraphConditionalAccessPolicy(
            id=graph_uuid(),
            displayName="Require MFA for admins",
            state="enabled",
            conditions={
                "users": {
                    "includeRoles": [
                        "Global Administrator",
                        "Security Administrator",
                    ],
                },
            },
            grantControls={
                "builtInControls": ["mfa"],
            },
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphConditionalAccessPolicy(
            id=graph_uuid(),
            displayName="Block legacy authentication",
            state="enabled",
            conditions={
                "clientAppTypes": ["exchangeActiveSync", "other"],
            },
            grantControls={
                "builtInControls": ["block"],
            },
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphConditionalAccessPolicy(
            id=graph_uuid(),
            displayName="Require compliant device",
            state="enabled",
            conditions={
                "users": {
                    "includeUsers": ["All"],
                },
            },
            grantControls={
                "builtInControls": ["compliantDevice"],
            },
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphConditionalAccessPolicy(
            id=graph_uuid(),
            displayName="Require MFA for risky sign-ins",
            state="enabled",
            conditions={
                "signInRiskLevels": ["high", "medium"],
            },
            grantControls={
                "builtInControls": ["mfa"],
            },
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphConditionalAccessPolicy(
            id=graph_uuid(),
            displayName="Session timeout after 1h",
            state="enabled",
            sessionControls={
                "signInFrequency": {"value": 1, "type": "hours"},
            },
            createdDateTime=now,
            modifiedDateTime=now,
        ),
        GraphConditionalAccessPolicy(
            id=graph_uuid(),
            displayName="Block countries (report-only)",
            state="enabledForReportingButNotEnforced",
            conditions={
                "locations": {
                    "includeLocations": ["blocked-countries-id"],
                },
            },
            createdDateTime=now,
            modifiedDateTime=now,
        ),
    ]

    for policy in policies:
        graph_ca_policy_repo.save(policy)
