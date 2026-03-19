"""Seed Microsoft Graph Compliance Policies and Device Configuration profiles."""
from __future__ import annotations

from faker import Faker

from domain.graph.compliance_policy import GraphCompliancePolicy
from domain.graph.device_configuration import GraphDeviceConfiguration
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import graph_uuid
from repository.graph.compliance_policy_repo import graph_compliance_policy_repo
from repository.graph.device_configuration_repo import graph_device_configuration_repo


def seed_graph_compliance(fake: Faker) -> None:
    """Create Intune compliance policies and device configuration profiles."""
    # -----------------------------------------------------------------
    # Compliance Policies
    # -----------------------------------------------------------------
    compliance_policies = [
        GraphCompliancePolicy(
            id=graph_uuid(),
            displayName="Windows 10 Baseline",
            description="Baseline compliance policy for Windows 10 endpoints",
            odata_type="#microsoft.graph.windows10CompliancePolicy",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
        GraphCompliancePolicy(
            id=graph_uuid(),
            displayName="macOS Security",
            description="Compliance policy for macOS devices",
            odata_type="#microsoft.graph.macOSCompliancePolicy",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
        GraphCompliancePolicy(
            id=graph_uuid(),
            displayName="iOS Corporate",
            description="Compliance policy for corporate iOS devices",
            odata_type="#microsoft.graph.iosCompliancePolicy",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
        GraphCompliancePolicy(
            id=graph_uuid(),
            displayName="Android Enterprise",
            description="Compliance policy for Android Enterprise devices",
            odata_type="#microsoft.graph.androidCompliancePolicy",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
        GraphCompliancePolicy(
            id=graph_uuid(),
            displayName="BitLocker Required",
            description="Windows compliance policy requiring BitLocker encryption",
            odata_type="#microsoft.graph.windows10CompliancePolicy",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=2,
        ),
    ]

    for policy in compliance_policies:
        graph_compliance_policy_repo.save(policy)

    # -----------------------------------------------------------------
    # Device Configuration Profiles
    # -----------------------------------------------------------------
    device_configurations = [
        GraphDeviceConfiguration(
            id=graph_uuid(),
            displayName="Windows Defender AV",
            description="Windows Defender Antivirus endpoint protection configuration",
            odata_type="#microsoft.graph.windows10EndpointProtectionConfiguration",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
        GraphDeviceConfiguration(
            id=graph_uuid(),
            displayName="Firewall Policy",
            description="Windows 10 network boundary and firewall configuration",
            odata_type="#microsoft.graph.windows10NetworkBoundaryConfiguration",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
        GraphDeviceConfiguration(
            id=graph_uuid(),
            displayName="Endpoint Protection",
            description="General Windows 10 endpoint protection settings",
            odata_type="#microsoft.graph.windows10GeneralConfiguration",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=2,
        ),
        GraphDeviceConfiguration(
            id=graph_uuid(),
            displayName="Wi-Fi Profile",
            description="Corporate Wi-Fi configuration profile",
            odata_type="#microsoft.graph.windowsWifiConfiguration",
            createdDateTime=rand_ago(max_days=180),
            lastModifiedDateTime=rand_ago(max_days=30),
            version=1,
        ),
    ]

    for config in device_configurations:
        graph_device_configuration_repo.save(config)
