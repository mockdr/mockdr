"""Seed Microsoft Graph Intune App Management data (app protection policies + mobile apps)."""
from __future__ import annotations

from faker import Faker

from domain.graph.app_protection_policy import GraphAppProtectionPolicy
from domain.graph.mobile_app import GraphMobileApp
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.app_protection_policy_repo import graph_app_protection_policy_repo
from repository.graph.mobile_app_repo import graph_mobile_app_repo

# ---------------------------------------------------------------------------
# Static data for app protection policies
# ---------------------------------------------------------------------------

_APP_PROTECTION_POLICIES: list[dict] = [
    {
        "displayName": "iOS Corporate Data Protection",
        "description": "Strict MAM policy for corporate iOS apps",
        "odata_type": "#microsoft.graph.iosManagedAppProtection",
        "pinRequired": True,
        "minimumPinLength": 6,
        "allowedDataStorageLocations": ["oneDriveForBusiness", "sharePoint"],
        "dataBackupBlocked": True,
        "organizationalCredentialsRequired": True,
    },
    {
        "displayName": "Android Enterprise Protection",
        "description": "Strict MAM policy for corporate Android apps",
        "odata_type": "#microsoft.graph.androidManagedAppProtection",
        "pinRequired": True,
        "minimumPinLength": 6,
        "allowedDataStorageLocations": ["oneDriveForBusiness", "sharePoint"],
        "dataBackupBlocked": True,
        "organizationalCredentialsRequired": True,
    },
    {
        "displayName": "iOS BYOD Minimal",
        "description": "Minimal MAM policy for BYOD iOS devices",
        "odata_type": "#microsoft.graph.iosManagedAppProtection",
        "pinRequired": True,
        "minimumPinLength": 4,
        "allowedDataStorageLocations": ["oneDriveForBusiness", "sharePoint", "localStorage"],
        "dataBackupBlocked": False,
        "organizationalCredentialsRequired": False,
    },
    {
        "displayName": "Android BYOD Minimal",
        "description": "Minimal MAM policy for BYOD Android devices",
        "odata_type": "#microsoft.graph.androidManagedAppProtection",
        "pinRequired": True,
        "minimumPinLength": 4,
        "allowedDataStorageLocations": ["oneDriveForBusiness", "sharePoint", "localStorage"],
        "dataBackupBlocked": False,
        "organizationalCredentialsRequired": False,
    },
]

# ---------------------------------------------------------------------------
# Static data for mobile apps
# ---------------------------------------------------------------------------

_MOBILE_APPS: list[dict] = [
    {"displayName": "Microsoft Teams", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.iosVppApp"},
    {"displayName": "Outlook", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.androidStoreApp"},
    {"displayName": "Company Portal", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.win32LobApp"},
    {"displayName": "Chrome", "publisher": "Google LLC", "odata_type": "#microsoft.graph.webApp"},
    {"displayName": "Slack", "publisher": "Slack Technologies", "odata_type": "#microsoft.graph.iosStoreApp"},
    {"displayName": "Zoom", "publisher": "Zoom Video Communications", "odata_type": "#microsoft.graph.androidStoreApp"},
    {"displayName": "Power BI", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.windowsStoreApp"},
    {"displayName": "OneDrive", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.iosVppApp"},
    {"displayName": "SharePoint", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.androidManagedStoreApp"},
    {"displayName": "Authenticator", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.iosStoreApp"},
    {"displayName": "Excel", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.windowsUniversalAppX"},
    {"displayName": "Word", "publisher": "Microsoft Corporation", "odata_type": "#microsoft.graph.win32LobApp"},
]


def seed_graph_app_management(fake: Faker) -> None:
    """Create Intune app protection policies and mobile app records.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    # ── Seed app protection policies ──────────────────────────────────────
    for cfg in _APP_PROTECTION_POLICIES:
        created = rand_ago(max_days=180)
        modified = rand_ago(max_days=30)
        graph_app_protection_policy_repo.save(GraphAppProtectionPolicy(
            id=graph_uuid(),
            displayName=cfg["displayName"],
            description=cfg["description"],
            odata_type=cfg["odata_type"],
            pinRequired=cfg["pinRequired"],
            minimumPinLength=cfg["minimumPinLength"],
            allowedDataStorageLocations=cfg["allowedDataStorageLocations"],
            dataBackupBlocked=cfg["dataBackupBlocked"],
            organizationalCredentialsRequired=cfg["organizationalCredentialsRequired"],
            createdDateTime=created,
            lastModifiedDateTime=modified,
            version="1",
        ))

    # ── Seed mobile apps ──────────────────────────────────────────────────
    for app_cfg in _MOBILE_APPS:
        created = rand_ago(max_days=365)
        modified = rand_ago(max_days=60)
        graph_mobile_app_repo.save(GraphMobileApp(
            id=graph_uuid(),
            displayName=app_cfg["displayName"],
            description=f"{app_cfg['displayName']} managed by Intune",
            publisher=app_cfg["publisher"],
            odata_type=app_cfg["odata_type"],
            isFeatured=app_cfg["displayName"] in {"Microsoft Teams", "Outlook", "Company Portal"},
            createdDateTime=created,
            lastModifiedDateTime=modified,
        ))
