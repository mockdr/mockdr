"""Seed Microsoft Graph Windows Autopilot devices and deployment profiles."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.autopilot_device import GraphAutopilotDevice
from domain.graph.autopilot_profile import GraphAutopilotProfile
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.autopilot_device_repo import graph_autopilot_device_repo
from repository.graph.autopilot_profile_repo import graph_autopilot_profile_repo
from repository.graph.managed_device_repo import graph_managed_device_repo


def seed_graph_autopilot(fake: Faker) -> None:
    """Create Autopilot device identities and deployment profiles.

    Picks 20 Windows managed devices from the managed-device store and
    creates Autopilot records using their serial numbers and models.
    """
    # -----------------------------------------------------------------
    # Autopilot Devices — pick 20 Windows managed devices
    # -----------------------------------------------------------------
    all_devices = graph_managed_device_repo.list_all()
    windows_devices = [
        d for d in all_devices if d.operatingSystem == "Windows"
    ]

    # Take up to 20; if fewer exist, use what we have
    selected = random.sample(windows_devices, min(20, len(windows_devices)))

    # State distribution: 15 enrolled, 3 pendingReset, 2 notContacted
    states: list[str] = (
        ["enrolled"] * 15
        + ["pendingReset"] * 3
        + ["notContacted"] * 2
    )
    # Pad or trim to match selected length
    while len(states) < len(selected):
        states.append("enrolled")
    states = states[: len(selected)]
    random.shuffle(states)

    for device, state in zip(selected, states, strict=False):
        profile_status = (
            "assigned" if state == "enrolled"
            else "pending" if state == "pendingReset"
            else "notAssigned"
        )
        graph_autopilot_device_repo.save(GraphAutopilotDevice(
            id=graph_uuid(),
            serialNumber=device.serialNumber,
            manufacturer=device.manufacturer,
            model=device.model,
            groupTag="Corporate",
            purchaseOrderIdentifier=fake.bothify("PO-####-????").upper(),
            enrollmentState=state,
            lastContactedDateTime=rand_ago(max_days=30) if state != "notContacted" else "",
            deploymentProfileAssignmentStatus=profile_status,
        ))

    # -----------------------------------------------------------------
    # Deployment Profiles
    # -----------------------------------------------------------------
    profiles = [
        GraphAutopilotProfile(
            id=graph_uuid(),
            displayName="Standard User OOBE",
            description="Standard out-of-box experience for end-user driven deployment",
            outOfBoxExperienceSettings={
                "hidePrivacySettings": True,
                "hideEULA": True,
                "userType": "standard",
                "skipKeyboardSelectionPage": True,
            },
            enrollmentStatusScreenSettings={
                "hideInstallationProgress": False,
                "allowDeviceUseBeforeProfileAndAppInstallComplete": False,
                "blockDeviceSetupRetryByUser": False,
            },
        ),
        GraphAutopilotProfile(
            id=graph_uuid(),
            displayName="Kiosk Mode",
            description="Autopilot profile for kiosk/shared-device deployments",
            outOfBoxExperienceSettings={
                "hidePrivacySettings": True,
                "hideEULA": True,
                "userType": "standard",
                "skipKeyboardSelectionPage": True,
            },
            enrollmentStatusScreenSettings={
                "hideInstallationProgress": False,
                "allowDeviceUseBeforeProfileAndAppInstallComplete": False,
                "blockDeviceSetupRetryByUser": True,
            },
        ),
        GraphAutopilotProfile(
            id=graph_uuid(),
            displayName="Self-Deploying",
            description="Self-deploying Autopilot profile for zero-touch provisioning",
            outOfBoxExperienceSettings={
                "hidePrivacySettings": True,
                "hideEULA": True,
                "userType": "administrator",
                "skipKeyboardSelectionPage": True,
            },
            enrollmentStatusScreenSettings={
                "hideInstallationProgress": False,
                "allowDeviceUseBeforeProfileAndAppInstallComplete": True,
                "blockDeviceSetupRetryByUser": False,
            },
        ),
    ]

    for profile in profiles:
        graph_autopilot_profile_repo.save(profile)
