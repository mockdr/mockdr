"""Seed Microsoft Graph Intune update rings, enrollment restrictions, and device categories."""
from __future__ import annotations

from faker import Faker

from domain.graph.device_category import GraphDeviceCategory
from domain.graph.enrollment_restriction import GraphEnrollmentRestriction
from domain.graph.update_ring import GraphUpdateRing
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.device_category_repo import graph_device_category_repo
from repository.graph.enrollment_restriction_repo import graph_enrollment_restriction_repo
from repository.graph.update_ring_repo import graph_update_ring_repo

# ---------------------------------------------------------------------------
# Static data for update rings
# ---------------------------------------------------------------------------

_UPDATE_RINGS: list[dict] = [
    {
        "displayName": "Fast Ring (IT Test)",
        "description": "Zero deferral ring for IT testing",
        "qualityUpdatesDeferralPeriodInDays": 0,
        "featureUpdatesDeferralPeriodInDays": 0,
    },
    {
        "displayName": "Standard Ring (General)",
        "description": "Standard deferral ring for general users",
        "qualityUpdatesDeferralPeriodInDays": 7,
        "featureUpdatesDeferralPeriodInDays": 14,
    },
    {
        "displayName": "Deferred Ring (Finance)",
        "description": "Extended deferral ring for finance department",
        "qualityUpdatesDeferralPeriodInDays": 14,
        "featureUpdatesDeferralPeriodInDays": 30,
    },
]

# ---------------------------------------------------------------------------
# Static data for enrollment restrictions
# ---------------------------------------------------------------------------

_ENROLLMENT_RESTRICTIONS: list[dict] = [
    {
        "displayName": "Default Platform Restriction",
        "description": "Default platform enrollment restriction configuration",
        "odata_type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
        "priority": 0,
    },
    {
        "displayName": "Default Device Limit",
        "description": "Default device limit enrollment configuration",
        "odata_type": "#microsoft.graph.deviceEnrollmentLimitConfiguration",
        "priority": 0,
    },
]

# ---------------------------------------------------------------------------
# Static data for device categories
# ---------------------------------------------------------------------------

_DEVICE_CATEGORIES: list[str] = [
    "Corporate Laptop",
    "Shared Device",
    "Kiosk",
    "BYOD",
    "Executive",
]


def seed_graph_update_rings(fake: Faker) -> None:
    """Create Intune update rings, enrollment restrictions, and device categories.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    # ── Seed update rings ─────────────────────────────────────────────────
    for cfg in _UPDATE_RINGS:
        graph_update_ring_repo.save(GraphUpdateRing(
            id=graph_uuid(),
            displayName=cfg["displayName"],
            description=cfg["description"],
            qualityUpdatesDeferralPeriodInDays=cfg["qualityUpdatesDeferralPeriodInDays"],
            featureUpdatesDeferralPeriodInDays=cfg["featureUpdatesDeferralPeriodInDays"],
            autoInstallAtMaintenanceTime=True,
            deliveryOptimizationMode="httpOnly",
            createdDateTime=rand_ago(max_days=180),
        ))

    # ── Seed enrollment restrictions ──────────────────────────────────────
    for cfg in _ENROLLMENT_RESTRICTIONS:
        graph_enrollment_restriction_repo.save(GraphEnrollmentRestriction(
            id=graph_uuid(),
            displayName=cfg["displayName"],
            description=cfg["description"],
            odata_type=cfg["odata_type"],
            priority=cfg["priority"],
            createdDateTime=rand_ago(max_days=365),
        ))

    # ── Seed device categories ────────────────────────────────────────────
    for name in _DEVICE_CATEGORIES:
        graph_device_category_repo.save(GraphDeviceCategory(
            id=graph_uuid(),
            displayName=name,
            description=f"{name} device category",
        ))
