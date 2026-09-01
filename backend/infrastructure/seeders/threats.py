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
    _seeding_admin,
    rand_after,
    rand_ago,
)
from repository.agent_repo import agent_repo
from repository.threat_repo import threat_repo
from utils.id_gen import new_id

#: What each timeline entry says, and the activity type splunkd's own
#: `TimelineViewSchema` carries beside it. The numbers are SentinelOne's
#: activity types for these events, the same ones `/activities` reports.
#: (activity type, what happened, which kind of event it was). The third
#: goes in `secondaryDescription`, which the schema declares and the console
#: shows beside the line — the category the old shape called `type`.
_TIMELINE_EVENTS: tuple[tuple[int, str, str], ...] = (
    (4001, "Threat detected by Behavioral AI", "detection"),
    (2001, "File quarantined", "mitigation"),
    (2010, "Process terminated", "mitigation"),
    (3050, "Network connection blocked", "mitigation"),
    (1502, "Hash reputation checked", "system"),
    (3784, "Analyst marked as true positive", "analyst action"),
    (2004, "Remediation initiated", "mitigation"),
    (2005, "File deleted", "mitigation"),
    (2006, "Registry key removed", "mitigation"),
)


def _threat_timeline(threat_id: str, agent: object, sha1: str,
                     detected_at: str) -> list[dict]:
    """Build a timeline for one threat, in the shape its schema declares.

    `TimelineViewSchema` names sixteen members — `createdAt`,
    `activityType`, `primaryDescription` and the scope ids among them — and
    this built `{timestamp, type, event}` instead. The response is shaped
    strictly against that schema, so every one of those keys was dropped and
    the route answered eight records of empty strings dated 2018, which is
    the fixture's own example. A client reading a threat's history saw eight
    rows of nothing and no way to tell they were not the history.

    The events are ordered from the detection onwards, because a timeline
    that is not in order is not a timeline.
    """
    analyst = _seeding_admin()[0]
    chosen = random.sample(_TIMELINE_EVENTS, k=random.randint(4, 8))
    stamps = sorted(rand_after(detected_at, 3) for _ in chosen)
    return [
        {
            "id": new_id(),
            "createdAt": when,
            "updatedAt": when,
            "activityType": activity_type,
            "data": {"threatId": threat_id},
            "primaryDescription": description,
            "secondaryDescription": kind,
            "osFamily": getattr(agent, "osType", None),
            "hash": sha1,
            "agentUpdatedVersion": getattr(agent, "agentVersion", ""),
            # "The user who invoked the activity (If applicable)" — a string
            # in the swagger, with no null allowed. The analyst-driven event
            # names the admin this mock actually serves; the machine-driven
            # ones stay blank, because attributing a Behavioral AI detection
            # to a person is the kind of quiet wrongness we are hunting. The
            # swagger's own example id names nobody at all.
            "userId": analyst if kind == "analyst action" else "",
            "threatId": threat_id,
            "agentId": getattr(agent, "id", ""),
            "accountId": getattr(agent, "accountId", ""),
            "siteId": getattr(agent, "siteId", ""),
            "groupId": getattr(agent, "groupId", ""),
        }
        for when, (activity_type, description, kind) in zip(stamps, chosen, strict=True)
    ]


#: Signers a detected file carries. An empty string is the unsigned case,
#: which is most of what a detection engine sees.
_PUBLISHERS: list[str] = [
    "", "", "Microsoft Corporation", "Oracle America, Inc.",
    "Adobe Inc.", "VideoLAN", "Notepad++",
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
        # Drawn once: the timeline names the same file the
        # threat does, and a hash that differs from its own
        # threat is a hash nothing can be correlated by.
        threat_info_sha1 = fake.sha1()

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
            # The agent's own, so a threat and the endpoint it was found on
            # describe the same machine. It was `{}` on every threat, and the
            # two documented `cloudProvider` filters over it matched nothing.
            "cloudProviders": dict(agent.cloudProviders or {}),
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
                # A threat that has been raised with a ticketing system says
                # which ticket. Both were fixed at "no ticket, ever", so the
                # documented `externalTicketId` filters could match nothing.
                "externalTicketExists": (has_ticket := random.random() > 0.7),
                "externalTicketId": (
                    f"SOC-{random.randint(10000, 99999)}" if has_ticket else None
                ),
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
                # Who signed the file, which a signed binary carries and an
                # unsigned one does not.
                "publisherName": random.choice(_PUBLISHERS),
                "reachedEventsLimit": False,
                "rebootRequired": False,
                "rootProcessUpn": None,
                "sha1": threat_info_sha1,
                "sha256": fake.sha256(),
                "storyline": fake.lexify("????????????????").upper(),
                "threatId": tid,
                "threatName": fname,
                # Derived from the detection, not drawn beside it: three
                # threats in thirty were updated up to five days before
                # they existed, so "time to triage" came out negative.
                "updatedAt": rand_after(created_at, 10),
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
            timeline=_threat_timeline(
                tid, agent, threat_info_sha1, created_at),
        ))
