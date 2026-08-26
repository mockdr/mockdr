"""Seed Microsoft Graph Security data (alerts v2, incidents, secure scores, TI indicators)."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.secure_score import GraphSecureScore
from domain.graph.security_alert import GraphSecurityAlert
from domain.graph.security_incident import GraphSecurityIncident
from domain.graph.ti_indicator import GraphTiIndicator
from domain.mde_alert import MdeAlert
from infrastructure.seeders._shared import ago, rand_ago
from infrastructure.seeders.graph.graph_shared import GRAPH_TENANT_ID, graph_uuid
from repository.graph.secure_score_repo import graph_secure_score_repo
from repository.graph.security_alert_repo import graph_security_alert_repo
from repository.graph.security_incident_repo import graph_security_incident_repo
from repository.graph.ti_indicator_repo import graph_ti_indicator_repo
from repository.mde_alert_repo import mde_alert_repo
from repository.mde_indicator_repo import mde_indicator_repo
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
        last_update_dt = mde_alert.lastUpdateTime or rand_ago(max_days=5)

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
                "BenignPositive": "informationalExpectedActivity",
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
            detectionSource="customDetection",
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

        incident = GraphSecurityIncident(
            id=incident_id,
            displayName=f"Multi-stage attack involving {category_str}",
            severity=max_sev,
            status="active",
            classification=None,
            determination=None,
            assignedTo=None,
            createdDateTime=rand_ago(max_days=30),
            lastUpdateDateTime=rand_ago(max_days=5),
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

    # ── TI Indicators (mapped from MDE indicators) ────────────────────────
    mde_indicators = mde_indicator_repo.list_all()
    for mde_ind in mde_indicators:
        indicator_id = graph_uuid()
        observable, hash_type = _MDE_OBSERVABLE_MAP.get(
            mde_ind.indicatorType, ("fileHashValue", "sha256"))
        action = _MDE_ACTION_MAP.get(mde_ind.action, "alert")

        ti = GraphTiIndicator(
            id=indicator_id,
            action=action,
            azureTenantId=GRAPH_TENANT_ID,
            confidence=random.randint(50, 100),
            description=mde_ind.description,
            expirationDateTime=mde_ind.expirationTime or ago(days=-90),
            externalId=mde_ind.id,
            ingestedDateTime=mde_ind.creationTimeDateTimeUtc or rand_ago(max_days=60),
            isActive=True,
            killChain=random.choice([[], ["Delivery"], ["Installation"], ["C2"]]),
            malwareFamilyNames=random.choice([[], ["Emotet"], ["Trickbot"]]),
            passiveOnly=False,
            severity=random.randint(1, 5),
            tags=[],
            targetProduct="Microsoft Defender ATP",
            threatType="Malware",
            tlpLevel=random.choice(["white", "green", "amber", "red"]),
            lastReportedDateTime=mde_ind.lastUpdateTime or rand_ago(max_days=10),
            fileHashType=hash_type,
        )
        # The observable belongs in the property that names it, and which
        # property that is depends on the indicator's kind.
        setattr(ti, observable, mde_ind.indicatorValue)
        graph_ti_indicator_repo.save(ti)
