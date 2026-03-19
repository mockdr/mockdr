"""Seed Microsoft Graph Security data (alerts v2, incidents, secure scores, TI indicators)."""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.secure_score import GraphSecureScore
from domain.graph.security_alert import GraphSecurityAlert
from domain.graph.security_incident import GraphSecurityIncident
from domain.graph.ti_indicator import GraphTiIndicator
from infrastructure.seeders._shared import ago, rand_ago
from infrastructure.seeders.graph.graph_shared import GRAPH_TENANT_ID, graph_uuid
from repository.graph.secure_score_repo import graph_secure_score_repo
from repository.graph.security_alert_repo import graph_security_alert_repo
from repository.graph.security_incident_repo import graph_security_incident_repo
from repository.graph.ti_indicator_repo import graph_ti_indicator_repo
from repository.mde_alert_repo import mde_alert_repo
from repository.mde_indicator_repo import mde_indicator_repo
from repository.store import store

_MITRE_TECHNIQUES: list[str] = ["T1059", "T1053", "T1071", "T1082", "T1105"]

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

_MDE_INDICATOR_TYPE_MAP: dict[str, str] = {
    "FileSha256": "fileSha256",
    "FileSha1": "fileSha1",
    "IpAddress": "ipAddress",
    "DomainName": "domainName",
    "Url": "url",
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

        # Build evidence with device cross-reference
        evidence: list[dict] = []
        mapping = store.get("edr_id_map", mde_alert.machineId) or {}
        evidence.append({
            "type": "device",
            "deviceId": mapping.get("mde_machine_id", mde_alert.machineId),
        })

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

        incident_id = graph_uuid()
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

        # Link incidentId back to each alert in this group
        for alert in group:
            alert.incidentId = incident_id
            graph_security_alert_repo.save(alert)

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
        ind_type = _MDE_INDICATOR_TYPE_MAP.get(mde_ind.indicatorType, "fileSha256")
        action = _MDE_ACTION_MAP.get(mde_ind.action, "alert")

        ti = GraphTiIndicator(
            id=indicator_id,
            action=action,
            description=mde_ind.description,
            expirationDateTime=mde_ind.expirationTime or ago(days=-90),
            targetProduct="Microsoft Defender ATP",
            threatType="Malware",
            tlpLevel=random.choice(["white", "green", "amber", "red"]),
            indicatorValue=mde_ind.indicatorValue,
            indicatorType=ind_type,
            createdDateTime=mde_ind.creationTimeDateTimeUtc or rand_ago(max_days=60),
            lastReportedDateTime=mde_ind.lastUpdateTime or rand_ago(max_days=10),
        )
        graph_ti_indicator_repo.save(ti)
