"""Seed Microsoft Graph Managed Devices from existing S1 agent fleet."""
from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from faker import Faker

from domain.graph.managed_device import GraphManagedDevice
from infrastructure.seeders.graph.graph_shared import GRAPH_DOMAIN, graph_uuid
from repository.agent_repo import agent_repo
from repository.graph.managed_device_repo import graph_managed_device_repo
from repository.store import store

# ---------------------------------------------------------------------------
# OS mapping
# ---------------------------------------------------------------------------

_OS_MAP: dict[str, str] = {
    "windows": "Windows",
    "macos": "macOS",
    "linux": "Linux",
}

# ---------------------------------------------------------------------------
# Manufacturer / model pools per OS
# ---------------------------------------------------------------------------

_WINDOWS_MODELS: list[tuple[str, str]] = [
    ("Dell Inc.", "Latitude 5540"),
    ("Dell Inc.", "OptiPlex 7090"),
    ("Lenovo", "ThinkPad X1 Carbon Gen 11"),
    ("Lenovo", "ThinkCentre M920q"),
    ("HP", "EliteBook 840 G10"),
    ("HP", "ProDesk 400 G7"),
    ("Microsoft Corporation", "Surface Pro 9"),
    ("Microsoft Corporation", "Surface Laptop 5"),
]

_MACOS_MODELS: list[tuple[str, str]] = [
    ("Apple Inc.", "MacBook Pro (14-inch, 2023)"),
    ("Apple Inc.", "MacBook Air (M2, 2022)"),
    ("Apple Inc.", "Mac mini (M2, 2023)"),
    ("Apple Inc.", "iMac (24-inch, M3, 2023)"),
]

_LINUX_MODELS: list[tuple[str, str]] = [
    ("Dell Inc.", "PowerEdge R750"),
    ("Lenovo", "ThinkStation P360"),
    ("HP", "ProLiant DL380 Gen10"),
    ("Supermicro", "SYS-1029P-WTR"),
]

_MODEL_MAP: dict[str, list[tuple[str, str]]] = {
    "windows": _WINDOWS_MODELS,
    "macos": _MACOS_MODELS,
    "linux": _LINUX_MODELS,
}


def seed_graph_managed_devices(fake: Faker) -> None:
    """Create Intune managed-device records from existing S1 agent fleet.

    Reads every S1 agent from ``agent_repo`` and creates a corresponding
    ``GraphManagedDevice`` record with equivalent data in Graph API format.
    The device ID is stored in the ``edr_id_map`` for cross-EDR correlation.
    """
    s1_agents = agent_repo.list_all()
    total = len(s1_agents)

    for idx, agent in enumerate(s1_agents):
        device_id = graph_uuid()

        # Store agent↔device mapping for cross-EDR views
        mapping = store.get("edr_id_map", agent.id) or {}
        mapping["graph_managed_device_id"] = device_id
        store.save("edr_id_map", agent.id, mapping)

        # OS mapping
        operating_system = _OS_MAP.get(agent.osType, "Windows")
        os_version = agent.osName

        # Last sync: ~90% within 7 days, ~10% older
        if idx < int(total * 0.9):
            sync_offset = random.randint(0, 7 * 24 * 60)  # within 7 days (minutes)
        else:
            sync_offset = random.randint(7 * 24 * 60, 30 * 24 * 60)  # 7-30 days

        sync_dt = datetime.now(UTC) - timedelta(minutes=sync_offset)
        last_sync = sync_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Compliance distribution: 80% compliant, 15% noncompliant, 5% unknown
        compliance_roll = random.random()
        if compliance_roll < 0.80:
            compliance_state = "compliant"
        elif compliance_roll < 0.95:
            compliance_state = "noncompliant"
        else:
            compliance_state = "unknown"

        # Manufacturer / model based on OS
        models = _MODEL_MAP.get(agent.osType, _WINDOWS_MODELS)
        manufacturer, model = random.choice(models)

        # Serial number
        serial_number = fake.bothify("???-########").upper()

        # UPN from agent computerName
        upn = f"{agent.computerName.lower().replace(' ', '.')}@{GRAPH_DOMAIN}"

        # EOL OS devices get noncompliant state (OS already set from S1 agent)
        eol_markers = ("8.1", "1809", "Big Sur", "CentOS 7")
        if any(m in os_version for m in eol_markers):
            compliance_state = "noncompliant"

        graph_managed_device_repo.save(GraphManagedDevice(
            id=device_id,
            deviceName=agent.computerName,
            operatingSystem=operating_system,
            osVersion=os_version,
            lastSyncDateTime=last_sync,
            complianceState=compliance_state,
            managementState="managed",
            managedDeviceOwnerType="company",
            enrolledDateTime=agent.createdAt,
            userPrincipalName=upn,
            model=model,
            manufacturer=manufacturer,
            serialNumber=serial_number,
        ))

    # ── Add mobile/BYOD devices (not mapped from S1 fleet) ───────────
    mobile_devices = [
        ("iPhone 15 Pro", "iOS", "17.4.1", "Apple Inc.", "company"),
        ("iPhone 13", "iOS", "16.7.5", "Apple Inc.", "personal"),
        ("Samsung Galaxy S24", "Android", "14", "Samsung", "company"),
        ("Samsung Galaxy A54", "Android", "13", "Samsung", "personal"),
        ("Google Pixel 8", "Android", "14", "Google", "personal"),
        ("iPad Pro 12.9 (6th gen)", "iOS", "17.4.1", "Apple Inc.", "company"),
    ]
    for model_name, os_name, os_ver, mfg, owner_type in mobile_devices:
        dev_id = graph_uuid()
        sync_dt = datetime.now(UTC) - timedelta(days=random.randint(0, 14))
        graph_managed_device_repo.save(GraphManagedDevice(
            id=dev_id,
            deviceName=model_name,
            operatingSystem=os_name,
            osVersion=os_ver,
            lastSyncDateTime=sync_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            complianceState="compliant" if owner_type == "company" else "noncompliant",
            managementState="managed",
            managedDeviceOwnerType=owner_type,
            enrolledDateTime=sync_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            userPrincipalName=f"mobile.user{random.randint(1,5)}@{GRAPH_DOMAIN}",
            model=model_name,
            manufacturer=mfg,
            serialNumber=fake.bothify("???-########").upper(),
        ))
