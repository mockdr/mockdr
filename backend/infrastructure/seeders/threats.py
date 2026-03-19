"""Threats seeder — seeds the configured number of threat records."""
import random

from faker import Faker

from config import SEED_COUNT_THREATS
from domain.threat import Threat
from infrastructure.seeders._shared import (
    ANALYST_VERDICTS,
    CLASSIFICATIONS,
    CONFIDENCE_LEVELS,
    INCIDENT_STATUSES,
    MALWARE_FILES,
    MITIGATION_STATUSES,
    MITRE_TACTICS,
    MITRE_TECHNIQUES,
    rand_ago,
)
from repository.agent_repo import agent_repo
from repository.threat_repo import threat_repo
from utils.id_gen import new_id


def _threat_timeline(threat_id: str) -> list[dict]:
    """Build a synthetic timeline of events for a single threat.

    Args:
        threat_id: ID of the parent threat.

    Returns:
        List of timeline event dicts.
    """
    descriptions = [
        "Threat detected by Behavioral AI", "File quarantined",
        "Process terminated", "Network connection blocked",
        "Hash reputation checked", "Analyst marked as true positive",
        "Remediation initiated", "File deleted", "Registry key removed",
    ]
    return [
        {
            "id": new_id(),
            "threatId": threat_id,
            "timestamp": rand_ago(0),
            "type": random.choice(["detection", "mitigation", "user_action", "system"]),
            "event": random.choice(descriptions),
        }
        for _ in range(random.randint(4, 8))
    ]


def seed_threats(fake: Faker, agent_ids: list[str]) -> None:
    """Create ``SEED_COUNT_THREATS`` threat records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        agent_ids: Pool of agent IDs to randomly associate threats with.
    """
    for _ in range(SEED_COUNT_THREATS):
        tid = new_id()
        agent = agent_repo.get(random.choice(agent_ids))
        assert agent is not None
        fname = random.choice(MALWARE_FILES)
        incident_status = random.choice(INCIDENT_STATUSES)
        mitigation_status = random.choice(MITIGATION_STATUSES)
        analyst_verdict = random.choice(ANALYST_VERDICTS)
        classification = random.choice(CLASSIFICATIONS)
        confidence = random.choice(CONFIDENCE_LEVELS)
        created_at = rand_ago(60)

        detection_engines = random.sample(
            ["DBT - Behavioral AI", "Cloud", "Static AI", "Reputation",
             "Documents, Scripts", "Data Files"],
            k=random.randint(1, 2),
        )
        file_path = (
            f"\\Device\\HarddiskVolume3\\Users\\{fake.user_name()}"
            f"\\AppData\\Roaming\\{fake.word()}\\{fname}"
        )
        file_ext = fname.rsplit(".", 1)[-1].upper() if "." in fname else "EXE"
        initiated_by = random.choice([
            "agent_policy", "console_api", "on_demand_scan",
            "star_active", "star_manual", "cloud_detection",
        ])
        initiated_by_desc = {
            "agent_policy": "Agent Policy",
            "console_api": "Console API",
            "on_demand_scan": "On Demand Scan",
            "star_active": "STAR - Active",
            "star_manual": "STAR - Manual",
            "cloud_detection": "Cloud Detection",
        }.get(initiated_by, initiated_by)

        rti_ifaces = [
            {
                "id": iface["id"], "inet": iface["inet"],
                "inet6": iface["inet6"], "name": iface["name"],
                "physical": iface["physical"],
            }
            for iface in agent.networkInterfaces
        ]
        agent_realtime_info = {
            "accountId": agent.accountId, "accountName": agent.accountName,
            "activeThreats": agent.activeThreats,
            "agentComputerName": agent.computerName,
            "agentDecommissionedAt": None,
            "agentDomain": agent.domain,
            "agentId": agent.id,
            "agentInfected": agent.infected,
            "agentIsActive": agent.isActive,
            "agentIsDecommissioned": agent.isDecommissioned,
            "agentMachineType": agent.machineType,
            "agentMitigationMode": agent.mitigationMode,
            "agentNetworkStatus": agent.networkStatus,
            "agentOsName": agent.osName,
            "agentOsRevision": agent.osRevision,
            "agentOsType": agent.osType,
            "agentUuid": agent.uuid,
            "agentVersion": agent.agentVersion,
            "groupId": agent.groupId, "groupName": agent.groupName,
            "networkInterfaces": rti_ifaces,
            "operationalState": agent.operationalState,
            "rebootRequired": False,
            "scanAbortedAt": agent.scanAbortedAt,
            "scanFinishedAt": agent.scanFinishedAt,
            "scanStartedAt": agent.scanStartedAt,
            "scanStatus": agent.scanStatus,
            "siteId": agent.siteId, "siteName": agent.siteName,
            "storageName": None, "storageType": None,
            "userActionsNeeded": [],
        }
        agent_detection_info: dict[str, object] = {
            "accountId": agent.accountId, "accountName": agent.accountName,
            "agentComputerName": agent.computerName,
            "agentDetectionState": agent.detectionState,
            "agentDomain": agent.domain,
            "agentIpV4": agent.lastIpToMgmt,
            "agentIpV6": None,
            "agentLastLoggedInUpn": (
                f"{agent.lastLoggedInUserName.lower()}@acmecorp.internal"
                if agent.lastLoggedInUserName else None
            ),
            "agentLastLoggedInUserMail": None,
            "agentLastLoggedInUserName": agent.lastLoggedInUserName,
            "agentMitigationMode": agent.mitigationMode,
            "agentOsName": agent.osName,
            "agentOsRevision": agent.osRevision,
            "agentRegisteredAt": agent.registeredAt,
            "agentUuid": agent.uuid,
            "agentVersion": agent.agentVersion,
            "assetVersion": agent.agentVersion.split(".")[-1],
            "cloudProviders": {},
            "externalIp": agent.externalIp,
            "groupId": agent.groupId, "groupName": agent.groupName,
            "siteId": agent.siteId, "siteName": agent.siteName,
        }

        indicators = []
        for _ in range(random.randint(0, 2)):
            tactic = random.choice(MITRE_TACTICS)
            tech = random.choice(MITRE_TECHNIQUES)
            indicators.append({
                "category": random.choice([
                    "Exploitation", "Evasion", "Persistence", "Lateral Movement",
                ]),
                "description": fake.sentence(nb_words=6),
                "ids": [random.randint(10, 300)],
                "tactics": [{"name": tactic, "source": "MITRE", "techniques": [
                    {"link": f"https://attack.mitre.org/techniques/{tech}/",
                     "name": fake.bs().title()},
                ]}],
            })

        threat_repo.save(Threat(
            id=tid,
            threatInfo={
                "analystVerdict": analyst_verdict,
                "analystVerdictDescription": analyst_verdict.replace("_", " ").title(),
                "automaticallyResolved": False,
                "browserType": None,
                "certificateId": "",
                "classification": classification,
                "classificationSource": random.choice(["Cloud", "Static", "Engine"]),
                "cloudFilesHashVerdict": None,
                "collectionId": new_id(),
                "confidenceLevel": confidence,
                "createdAt": created_at,
                "detectionEngines": [
                    {"key": e.lower().replace(" ", "_"), "title": e}
                    for e in detection_engines
                ],
                "detectionType": random.choice(["static", "dynamic"]),
                "engines": detection_engines,
                "externalTicketExists": False,
                "externalTicketId": None,
                "failedActions": False,
                "fileExtension": file_ext,
                "fileExtensionType": random.choice(["Executable", "Document", "Script"]),
                "filePath": file_path,
                "fileSize": random.randint(10240, 5242880),
                "fileVerificationType": random.choice([
                    "NotSigned", "SignedVerified", "SignedInvalid",
                ]),
                "identifiedAt": created_at,
                "incidentStatus": incident_status,
                "incidentStatusDescription": incident_status.replace("_", " ").title(),
                "initiatedBy": initiated_by,
                "initiatedByDescription": initiated_by_desc,
                "initiatingUserId": None, "initiatingUsername": None,
                "isFileless": False, "isValidCertificate": False,
                "macroModules": [],
                "maliciousProcessArguments": f"\"{file_path}\"",
                "md5": fake.md5(),
                "mitigatedPreemptively": False,
                "mitigationStatus": mitigation_status,
                "mitigationStatusDescription": mitigation_status.replace("_", " ").title(),
                "originatorProcess": random.choice([
                    "msedge.exe", "outlook.exe", "winword.exe", "chrome.exe",
                ]),
                "pendingActions": False,
                "processUser": f"ACMECORP\\{fake.user_name().upper()}",
                "publisherName": "",
                "reachedEventsLimit": False,
                "rebootRequired": False,
                "rootProcessUpn": None,
                "sha1": fake.sha1(),
                "sha256": fake.sha256(),
                "storyline": fake.lexify("????????????????").upper(),
                "threatId": tid,
                "threatName": fname,
                "updatedAt": rand_ago(10),
            },
            agentDetectionInfo=agent_detection_info,
            agentRealtimeInfo=agent_realtime_info,
            indicators=indicators,
            mitigationStatus=[],
            whiteningOptions=random.sample(
                ["path", "file_type", "hash", "certificate"],
                k=random.randint(1, 3),
            ),
            notes=[],
            timeline=_threat_timeline(tid),
        ))
