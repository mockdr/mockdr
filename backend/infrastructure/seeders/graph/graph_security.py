"""Seed Microsoft Graph Security data (alerts v2, incidents, secure scores, TI indicators)."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.secure_score import GraphSecureScore
from domain.graph.security_alert import GraphSecurityAlert
from domain.graph.security_incident import GraphSecurityIncident
from domain.mde_alert import MdeAlert
from infrastructure.seeders._shared import ago, rand_after, rand_ago
from infrastructure.seeders.graph.graph_shared import GRAPH_TENANT_ID, graph_uuid
from repository.graph.secure_score_repo import graph_secure_score_repo
from repository.graph.security_alert_repo import graph_security_alert_repo
from repository.graph.security_incident_repo import graph_security_incident_repo
from repository.mde_alert_repo import mde_alert_repo
from repository.mde_machine_repo import mde_machine_repo

_MITRE_TECHNIQUES: list[str] = ["T1059", "T1053", "T1071", "T1082", "T1105"]

#: Defender spells these in upper camel case and Graph in lower; the members
#: are otherwise the same, and both lists come from
#: `data/vendor-specs/graph_v1.0_csdl_types.json`.
_GRAPH_HEALTH: dict[str, str] = {
    "Active": "active", "Inactive": "inactive",
    "ImpairedCommunication": "impairedCommunication",
    "NoSensorData": "noSensorData",
    "NoSensorDataImpairedCommunication": "noSensorDataImpairedCommunication",
}
_GRAPH_ONBOARDING: dict[str, str] = {
    "Onboarded": "onboarded", "CanBeOnboarded": "canBeOnboarded",
    "Unsupported": "unsupported", "InsufficientInfo": "insufficientInfo",
}
_GRAPH_RISK: dict[str, str] = {
    "None": "none", "Informational": "informational", "Low": "low",
    "Medium": "medium", "High": "high",
}


def _device_evidence(mde_alert: MdeAlert, created: str) -> dict:
    """One `microsoft.graph.security.deviceEvidence` for an alert's host.

    Built from the Defender machine the alert names, so the two products'
    views of one host agree and the reference resolves — `mdeDeviceId` is
    exactly the machine id Defender serves.
    """
    machine = mde_machine_repo.get(mde_alert.machineId)
    evidence: dict = {
        "@odata.type": "#microsoft.graph.security.deviceEvidence",
        "createdDateTime": created,
        "verdict": "unknown",
        "remediationStatus": "none",
        "remediationStatusDetails": None,
        "roles": ["compromised"],
        "detailedRoles": [],
        "tags": [],
        "mdeDeviceId": mde_alert.machineId,
        "azureAdDeviceId": getattr(machine, "aadDeviceId", "") or None,
        "deviceDnsName": getattr(machine, "computerDnsName", "") or None,
        "hostName": (getattr(machine, "computerDnsName", "") or "").split(".")[0] or None,
        "ntDomain": None,
        "dnsDomain": ".".join(
            (getattr(machine, "computerDnsName", "") or "").split(".")[1:]) or None,
        "osPlatform": getattr(machine, "osPlatform", "") or None,
        "osBuild": getattr(machine, "osBuild", 0) or None,
        "version": getattr(machine, "version", "") or None,
        "firstSeenDateTime": getattr(machine, "firstSeen", "") or None,
        "lastIpAddress": getattr(machine, "lastIpAddress", "") or None,
        "lastExternalIpAddress": getattr(machine, "lastExternalIpAddress", "") or None,
        "ipInterfaces": [ip for ip in [getattr(machine, "lastIpAddress", "")] if ip],
        "healthStatus": _GRAPH_HEALTH.get(getattr(machine, "healthStatus", ""), "unknown"),
        "onboardingStatus": _GRAPH_ONBOARDING.get(
            getattr(machine, "onboardingStatus", ""), "insufficientInfo"),
        "riskScore": _GRAPH_RISK.get(getattr(machine, "riskScore", ""), "none"),
        "defenderAvStatus": "updated",
        "rbacGroupId": getattr(machine, "rbacGroupId", 0) or None,
        "rbacGroupName": getattr(machine, "rbacGroupName", "") or None,
        "loggedOnUsers": [],
        "vmMetadata": None,
    }
    return evidence

_MDE_STATUS_MAP: dict[str, str] = {
    "New": "new",
    "InProgress": "inProgress",
    "Resolved": "resolved",
}

_MDE_SEVERITY_MAP: dict[str, str] = {
    "Informational": "informational",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
}

#: Defender's detection sources under the names `microsoft.graph.security
#: .detectionSource` declares. Every Graph alert here answered
#: `customDetection` whatever raised it, so a console grouping alerts by
#: where they came from drew one bar, and an alert Defender attributed to
#: its antivirus arrived in Graph as a custom detection.
_MDE_DETECTION_SOURCE_MAP: dict[str, str] = {
    "CustomDetection": "customDetection",
    "WindowsDefenderAv": "antivirus",
    "AutomatedInvestigation": "automatedInvestigation",
    "WindowsDefenderAtp": "microsoftDefenderForEndpoint",
    # Defender's own third-party feed has no member of its own in Graph's
    # vocabulary; `unknown` is the sentinel the enum declares for that.
    "ThirdPartyApis": "unknown",
}

#: And the state of the investigation behind it. Defender leaves this empty
#: on an alert nothing has investigated, which `unknown` is the enum's word
#: for; the answer carried null, which is not a member at all.
_MDE_INVESTIGATION_STATE_MAP: dict[str, str] = {
    "SuccessfullyRemediated": "successfullyRemediated",
    "Benign": "benign",
    "": "unknown",
}


_SEVERITY_RANK: dict[str, int] = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}

#: Where an MDE indicator's value belongs on a ``tiIndicator``. Graph has no
#: ``indicatorValue``: the observable goes in the property that names it, and
#: a file hash carries its algorithm in ``fileHashType`` beside it.
_MDE_OBSERVABLE_MAP: dict[str, tuple[str, str | None]] = {
    "FileSha256": ("fileHashValue", "sha256"),
    "FileSha1": ("fileHashValue", "sha1"),
    "FileMd5": ("fileHashValue", "md5"),
    "IpAddress": ("networkDestinationIPv4", None),
    "DomainName": ("domainName", None),
    "Url": ("url", None),
}

_MDE_ACTION_MAP: dict[str, str] = {
    "Alert": "alert",
    "AlertAndBlock": "block",
    "Allowed": "allow",
    "Block": "block",
    "Warn": "alert",
    "Audit": "alert",
    "BlockAndRemediate": "block",
}

_CONTROL_SCORE_NAMES: list[str] = [
    "MFARegistration",
    "AdminMFAV2",
    "BlockLegacyAuthentication",
    "RoleOverlap",
    "SigninRiskPolicy",
    "UserRiskPolicy",
    "IntegratedApps",
    "OneAdmin",
]



def _incident_state(group: list[GraphSecurityAlert]) -> tuple[str, str | None, str | None]:
    """What an incident's own status, classification and determination are.

    An incident is the alerts it groups, and in Microsoft 365 Defender its
    state follows theirs: it is resolved once they all are, in progress once
    somebody has started, and active otherwise; and where its alerts agree on
    a classification, the incident carries it.

    Every incident here was born `active` with neither field set, so 15 of 15
    had the same status and none could be filtered by any other, while the
    alerts underneath them were new, in progress and resolved. Two members of
    `incidentStatus` stay unseeded on purpose -- `redirected` means merged
    into another incident and `awaitingAction` means a pending approval, and
    this mock models neither, so answering with them would be a claim about
    a relationship nothing here has.

    Args:
        group: The alerts this incident groups.

    Returns:
        The incident's status, and its classification and determination
        where its alerts agree on one.
    """
    statuses = {alert.status for alert in group}
    if statuses == {"resolved"}:
        status = "resolved"
    elif statuses & {"inProgress", "resolved"}:
        status = "inProgress"
    else:
        status = "active"

    classifications = {a.classification for a in group if a.classification}
    determinations = {a.determination for a in group if a.determination}
    classification = classifications.pop() if len(classifications) == 1 else None
    determination = determinations.pop() if len(determinations) == 1 else None
    return status, classification, determination


def seed_graph_security(fake: Faker) -> None:
    """Seed Graph Security alerts v2, incidents, secure scores, and TI indicators.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    # ── Alerts v2 (mapped from MDE alerts) ────────────────────────────────
    mde_alerts = mde_alert_repo.list_all()
    graph_alerts: list[GraphSecurityAlert] = []

    for mde_alert in mde_alerts:
        alert_id = graph_uuid()
        severity = _MDE_SEVERITY_MAP.get(mde_alert.severity, "medium")
        status = _MDE_STATUS_MAP.get(mde_alert.status, "new")
        created_dt = mde_alert.alertCreationTime or rand_ago(max_days=30)
        # Derived from the creation above when the alert carries no update
        # of its own: two independent fallbacks let an incident be updated
        # before it was raised.
        last_update_dt = mde_alert.lastUpdateTime or rand_after(created_dt, 30)

        # Graph's alert evidence is a typed object, not a pair of invented
        # keys. `microsoft.graph.security.deviceEvidence` names the device
        # twice — `mdeDeviceId` for Defender's id and `azureAdDeviceId` for
        # the directory's — and carries the host's own description beside
        # them, which is what a client reads to decide what it is looking at.
        evidence: list[dict] = [_device_evidence(mde_alert, created_dt)]

        # Classification / determination for resolved alerts
        classification: str | None = None
        determination: str | None = None
        resolved_dt: str | None = None
        if mde_alert.classification:
            cls_map = {
                "TruePositive": "truePositive",
                "FalsePositive": "falsePositive",
                "Informational, expected activity": "informationalExpectedActivity",
            }
            classification = cls_map.get(mde_alert.classification)
        if mde_alert.determination:
            det_map = {
                "Malware": "malware",
                "NotMalware": "other",
                "Phishing": "phishing",
                "Other": "other",
            }
            determination = det_map.get(mde_alert.determination)
        if status == "resolved" and mde_alert.resolvedTime:
            resolved_dt = mde_alert.resolvedTime

        alert = GraphSecurityAlert(
            id=alert_id,
            providerAlertId=mde_alert.alertId,
            status=status,
            severity=severity,
            classification=classification,
            determination=determination,
            serviceSource="microsoftDefenderForEndpoint",
            detectionSource=_MDE_DETECTION_SOURCE_MAP.get(
                mde_alert.detectionSource, "unknown"),
            investigationState=_MDE_INVESTIGATION_STATE_MAP.get(
                mde_alert.investigationState, "unknown"),
            title=mde_alert.title,
            description=mde_alert.description,
            category=mde_alert.category,
            assignedTo=mde_alert.assignedTo or None,
            createdDateTime=created_dt,
            lastUpdateDateTime=last_update_dt,
            resolvedDateTime=resolved_dt,
            firstActivityDateTime=mde_alert.firstEventTime or created_dt,
            lastActivityDateTime=mde_alert.lastEventTime or created_dt,
            alertWebUrl=f"https://security.microsoft.com/alerts/{alert_id}",
            tenantId=GRAPH_TENANT_ID,
            evidence=evidence,
            comments=[],
            mitreTechniques=random.sample(
                _MITRE_TECHNIQUES,
                k=random.randint(1, 3),
            ),
        )
        graph_security_alert_repo.save(alert)
        graph_alerts.append(alert)

    # ── Incidents (15, grouping alerts 2-3 per incident) ──────────────────
    incident_count = 15
    random.shuffle(graph_alerts)
    chunk_size = max(1, len(graph_alerts) // incident_count)

    for i in range(incident_count):
        start = i * chunk_size
        end = start + chunk_size if i < incident_count - 1 else len(graph_alerts)
        group = graph_alerts[start:end]
        if not group:
            continue

        # Determine max severity from grouped alerts
        max_sev = max(
            (a.severity for a in group),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
        )

        # Defender numbers its incidents. The Graph alert names its incident
        # with a string (`incidentId` is `Edm.String` in the CSDL) and the
        # Defender alert reports the same incident as a number — the Splunk
        # add-on's sample declares `incidentId` a number. A GUID here left
        # every Defender alert naming an incident nothing had, and the two
        # products disagreeing about which incident an alert belongs to.
        incident_number = i + 1
        incident_id = str(incident_number)
        alert_ids = [a.id for a in group]
        categories = {a.category for a in group if a.category}
        category_str = next(iter(categories)) if categories else "SuspiciousActivity"

        status, classification, determination = _incident_state(group)
        incident = GraphSecurityIncident(
            id=incident_id,
            displayName=f"Multi-stage attack involving {category_str}",
            severity=max_sev,
            status=status,
            classification=classification,
            determination=determination,
            assignedTo=None,
            # An incident spans the alerts it groups: it began when the
            # first of them did and was last touched when the last of them
            # was. Two independent draws had one incident updated a day
            # before it was raised, and none of them lined up with the
            # alerts they are made of.
            createdDateTime=min(a.createdDateTime for a in group),
            lastUpdateDateTime=max(a.lastUpdateDateTime for a in group),
            alert_ids=alert_ids,
            comments=[],
            tenantId=GRAPH_TENANT_ID,
            incidentWebUrl=f"https://security.microsoft.com/incidents/{incident_id}",
        )
        graph_security_incident_repo.save(incident)

        # Link the incident back to each alert in this group — on both
        # surfaces, so a client that reads the Defender alert and a client
        # that reads the Graph alert land on the same incident.
        for alert in group:
            alert.incidentId = incident_id
            graph_security_alert_repo.save(alert)
            source = mde_alert_repo.get(alert.providerAlertId)
            if source is not None:
                source.incidentId = incident_number
                mde_alert_repo.save(source)

    # ── Secure Scores (30 daily snapshots) ────────────────────────────────
    for day_index in range(30):
        score_id = graph_uuid()
        base_score = 60.0 + (day_index * 0.67) + random.uniform(-2.0, 2.0)
        current_score = round(min(100.0, max(0.0, base_score)), 1)

        control_scores: list[dict] = [
            {"controlName": "MFARegistrationV2", "score": round(random.uniform(5, 9), 1), "maxScore": 10.0},
            {"controlName": "BlockLegacyAuthentication", "score": round(random.uniform(6, 10), 1), "maxScore": 10.0},
            {"controlName": "AdminMFAV2", "score": round(random.uniform(4, 8), 1), "maxScore": 10.0},
            {"controlName": "IntegratedApps", "score": round(random.uniform(3, 7), 1), "maxScore": 10.0},
            {"controlName": "RoleOverlap", "score": round(random.uniform(5, 9), 1), "maxScore": 10.0},
        ]

        score = GraphSecureScore(
            id=score_id,
            azureTenantId=GRAPH_TENANT_ID,
            currentScore=current_score,
            maxScore=100.0,
            createdDateTime=ago(days=30 - day_index),
            controlScores=control_scores,
        )
        graph_secure_score_repo.save(score)
