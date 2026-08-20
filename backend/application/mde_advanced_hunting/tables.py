"""Advanced Hunting tables, projected from the seeded store.

Hunting queries run against named schema tables rather than the REST
resources, so each table is derived here from the same data the REST endpoints
serve. That keeps a hunting result consistent with what ``/api/machines`` and
``/api/alerts`` report, which is the property that makes a hunting query worth
testing against a mock at all.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from repository.mde_alert_repo import mde_alert_repo
from repository.mde_machine_repo import mde_machine_repo
from repository.mde_software_repo import mde_software_repo
from repository.mde_vulnerability_repo import mde_vulnerability_repo

__all__ = ["TABLE_NAMES", "get_table"]

Row = dict[str, Any]


def _device_info() -> list[Row]:
    return [
        {
            "Timestamp": m.lastSeen,
            "DeviceId": m.machineId,
            "DeviceName": m.computerDnsName,
            "ClientVersion": m.agentVersion,
            "PublicIP": m.lastExternalIpAddress,
            "OSArchitecture": m.osProcessor,
            "OSPlatform": m.osPlatform,
            "OSBuild": m.osBuild,
            "OSVersion": m.osVersion,
            "MachineGroup": m.rbacGroupName,
            "OnboardingStatus": m.onboardingStatus,
            "HealthStatus": m.healthStatus,
            "RiskScore": m.riskScore,
            "ExposureLevel": m.exposureLevel,
        }
        for m in mde_machine_repo.list_all()
    ]


def _alert_info() -> list[Row]:
    return [
        {
            "Timestamp": a.alertCreationTime,
            "AlertId": a.alertId,
            "Title": a.title,
            "Category": a.category,
            "Severity": a.severity,
            "ServiceSource": a.detectionSource,
            "DetectionSource": a.detectionSource,
            "Status": a.status,
            "Classification": a.classification,
            "Determination": a.determination,
        }
        for a in mde_alert_repo.list_all()
    ]


def _alert_evidence() -> list[Row]:
    names = {m.machineId: m.computerDnsName for m in mde_machine_repo.list_all()}
    return [
        {
            "Timestamp": a.alertCreationTime,
            "AlertId": a.alertId,
            "DeviceId": a.machineId,
            "DeviceName": names.get(a.machineId, ""),
            "EntityType": "Machine",
            "EvidenceRole": "Impacted",
            "Title": a.title,
            "Severity": a.severity,
            "Categories": a.category,
        }
        for a in mde_alert_repo.list_all()
    ]


def _device_software_inventory() -> list[Row]:
    machines = mde_machine_repo.list_all()
    software = mde_software_repo.list_all()
    if not machines or not software:
        return []
    return [
        {
            "DeviceId": machine.machineId,
            "DeviceName": machine.computerDnsName,
            "OSPlatform": machine.osPlatform,
            "SoftwareVendor": entry.vendor,
            "SoftwareName": entry.name,
            "SoftwareVersion": entry.version,
        }
        for index, machine in enumerate(machines)
        # Round-robin, matching how /software/{id}/machineReferences pairs them.
        for entry in software[index % len(software) :: len(software)]
    ]


def _device_software_vulnerabilities() -> list[Row]:
    machines = mde_machine_repo.list_all()
    vulns = mde_vulnerability_repo.list_all()
    if not machines or not vulns:
        return []
    return [
        {
            "DeviceId": machine.machineId,
            "DeviceName": machine.computerDnsName,
            "OSPlatform": machine.osPlatform,
            "CveId": vuln.vulnerabilityId,
            "VulnerabilitySeverityLevel": vuln.severity,
            "CvssScore": vuln.cvssV3,
            "IsExploitAvailable": vuln.publicExploit,
        }
        for index, machine in enumerate(machines)
        for vuln in vulns[index % len(vulns) :: len(vulns)]
    ]


#: Tables this mock backs. A query naming anything else is an error, the way
#: Defender rejects an unknown table, rather than silently returning rows.
_TABLES: dict[str, Callable[[], list[Row]]] = {
    "DeviceInfo": _device_info,
    "AlertInfo": _alert_info,
    "AlertEvidence": _alert_evidence,
    "DeviceTvmSoftwareInventory": _device_software_inventory,
    "DeviceTvmSoftwareVulnerabilities": _device_software_vulnerabilities,
}

TABLE_NAMES: tuple[str, ...] = tuple(sorted(_TABLES))


def get_table(name: str) -> list[Row] | None:
    """Return the rows of *name*, or None when the table is unknown."""
    for table, builder in _TABLES.items():
        if table.lower() == name.lower():
            return builder()
    return None
