"""Seed Microsoft Graph Sign-In Logs with realistic authentication events."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.sign_in_log import GraphSignInLog
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.sign_in_log_repo import graph_sign_in_log_repo
from repository.graph.user_repo import graph_user_repo

# ---------------------------------------------------------------------------
# Application pools
# ---------------------------------------------------------------------------

_APP_POOL: list[tuple[str, str]] = [
    (graph_uuid(), "Microsoft Teams"),
    (graph_uuid(), "Office 365 Exchange Online"),
    (graph_uuid(), "Microsoft 365 Portal"),
    (graph_uuid(), "Microsoft Graph Explorer"),
]

_CLIENT_APPS: list[str] = [
    "Browser",
    "Mobile Apps and Desktop clients",
    "Exchange ActiveSync",
]

_CLIENT_APP_WEIGHTS: list[int] = [50, 40, 10]

# ---------------------------------------------------------------------------
# Risk-level distribution
# ---------------------------------------------------------------------------

_RISK_LEVELS: list[str] = ["none", "low", "medium", "high"]
_RISK_WEIGHTS: list[int] = [85, 10, 4, 1]

_ENTRY_COUNT: int = 200


def seed_graph_sign_in_logs(fake: Faker, user_ids: list[str]) -> None:
    """Create 200 sign-in log entries over the last 30 days.

    Distributes events across users with weighted probability toward
    active users and mixes success, MFA, failure, and CA-blocked outcomes.

    Args:
        fake:     Shared Faker instance (seeded externally).
        user_ids: List of Graph user ID strings to reference.
    """
    if not user_ids:
        return

    # Build user lookup for display names / UPNs
    user_details: dict[str, dict[str, str]] = {}
    for uid in user_ids:
        user = graph_user_repo.get(uid)
        if user is not None:
            user_details[uid] = {
                "displayName": user.displayName,
                "upn": user.userPrincipalName,
            }
        else:
            user_details[uid] = {
                "displayName": "Unknown User",
                "upn": "unknown@acmecorp.onmicrosoft.com",
            }

    # Weight toward first ~60 % of users (more active)
    active_cutoff = max(1, int(len(user_ids) * 0.6))
    weights = [3] * active_cutoff + [1] * (len(user_ids) - active_cutoff)

    for _ in range(_ENTRY_COUNT):
        uid = random.choices(user_ids, weights=weights, k=1)[0]
        details = user_details[uid]
        app_id, app_name = random.choice(_APP_POOL)

        # Outcome distribution: 70% success, 15% MFA, 10% failed pw, 5% CA blocked
        roll = random.random()
        if roll < 0.70:
            # Successful sign-in
            status = {"errorCode": 0, "failureReason": ""}
            ca_status = "notApplied"
        elif roll < 0.85:
            # MFA required — successful after MFA
            status = {"errorCode": 0, "failureReason": ""}
            ca_status = "success"
        elif roll < 0.95:
            # Failed password
            status = {"errorCode": 50126, "failureReason": "Invalid username or password"}
            ca_status = "notApplied"
        else:
            # Blocked by Conditional Access
            status = {"errorCode": 53003, "failureReason": "Blocked by Conditional Access"}
            ca_status = "failure"

        # Risk levels
        risk = random.choices(_RISK_LEVELS, weights=_RISK_WEIGHTS, k=1)[0]

        # Location
        city = fake.city()
        state = fake.state()
        country = fake.country_code()
        location = {
            "city": city,
            "state": state,
            "countryOrRegion": country,
            "geoCoordinates": {
                "latitude": float(fake.latitude()),
                "longitude": float(fake.longitude()),
            },
        }

        # Resource mirrors app
        resource_id = app_id
        resource_display = app_name

        graph_sign_in_log_repo.save(GraphSignInLog(
            id=graph_uuid(),
            createdDateTime=rand_ago(max_days=30),
            userDisplayName=details["displayName"],
            userPrincipalName=details["upn"],
            userId=uid,
            appId=app_id,
            appDisplayName=app_name,
            ipAddress=fake.ipv4_public(),
            clientAppUsed=random.choices(_CLIENT_APPS, weights=_CLIENT_APP_WEIGHTS, k=1)[0],
            location=location,
            status=status,
            conditionalAccessStatus=ca_status,
            isInteractive=random.random() < 0.75,
            riskLevelAggregated=risk,
            riskLevelDuringSignIn=risk,
            riskState="none" if risk == "none" else "atRisk",
            resourceDisplayName=resource_display,
            resourceId=resource_id,
            appliedConditionalAccessPolicies=[],
        ))
