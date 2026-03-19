"""Seed Microsoft Graph Identity Protection data (risky users + risk detections)."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.risk_detection import GraphRiskDetection
from domain.graph.risky_user import GraphRiskyUser
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.risk_detection_repo import graph_risk_detection_repo
from repository.graph.risky_user_repo import graph_risky_user_repo
from repository.graph.user_repo import graph_user_repo

# Risk event types with target counts (15 total)
_RISK_EVENT_DISTRIBUTION: list[str] = [
    "anonymizedIPAddress",
    "anonymizedIPAddress",
    "anonymizedIPAddress",
    "unfamiliarFeatures",
    "unfamiliarFeatures",
    "unfamiliarFeatures",
    "malwareInfectedIPAddress",
    "malwareInfectedIPAddress",
    "leakedCredentials",
    "leakedCredentials",
    "passwordSpray",
    "passwordSpray",
    "passwordSpray",
    "impossibleTravel",
    "impossibleTravel",
]


def seed_graph_identity_protection(fake: Faker, user_ids: list[str]) -> None:
    """Create 5 risky users and 15 risk detections linked to them.

    Args:
        fake:     Shared Faker instance (seeded externally).
        user_ids: List of existing Graph user ID strings.
    """
    # Pick 5 users to flag as risky
    risky_user_ids = random.sample(user_ids, min(5, len(user_ids)))

    # ── Seed risky users ──────────────────────────────────────────────────
    risk_configs: list[tuple[str, str, str]] = [
        ("high", "atRisk", "none"),
        ("high", "atRisk", "none"),
        ("medium", "atRisk", "none"),
        ("medium", "atRisk", "none"),
        ("low", "dismissed", "userPerformedSecuredPasswordReset"),
    ]

    for uid, (level, state, detail) in zip(risky_user_ids, risk_configs, strict=False):
        user = graph_user_repo.get(uid)
        upn = user.userPrincipalName if user else ""
        display_name = user.displayName if user else ""

        risky_user = GraphRiskyUser(
            id=uid,
            userPrincipalName=upn,
            userDisplayName=display_name,
            riskLevel=level,
            riskState=state,
            riskDetail=detail,
            riskLastUpdatedDateTime=rand_ago(max_days=30),
            isProcessing=False,
            isDeleted=False,
        )
        graph_risky_user_repo.save(risky_user)

    # ── Seed risk detections ──────────────────────────────────────────────
    event_types = list(_RISK_EVENT_DISTRIBUTION)
    random.shuffle(event_types)

    for i, event_type in enumerate(event_types):
        # Distribute detections across the 5 risky users (3 each)
        target_uid = risky_user_ids[i % len(risky_user_ids)]
        user = graph_user_repo.get(target_uid)
        upn = user.userPrincipalName if user else ""
        display_name = user.displayName if user else ""

        detected_dt = rand_ago(max_days=30)
        risk_level = random.choice(["low", "medium", "high"])

        detection = GraphRiskDetection(
            id=graph_uuid(),
            userId=target_uid,
            userPrincipalName=upn,
            userDisplayName=display_name,
            riskEventType=event_type,
            riskLevel=risk_level,
            riskState="atRisk",
            riskDetail="none",
            ipAddress=fake.ipv4_public(),
            location={
                "city": fake.city(),
                "state": fake.state(),
                "countryOrRegion": fake.country_code(),
            },
            detectedDateTime=detected_dt,
            lastUpdatedDateTime=detected_dt,
            activityDateTime=detected_dt,
            detectionTimingType=random.choice(["realtime", "offline"]),
            activity="signin",
            source="IdentityProtection",
            tokenIssuerType="AzureAD",
        )
        graph_risk_detection_repo.save(detection)
