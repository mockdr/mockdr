"""MDE alerts seeder -- generates realistic Defender for Endpoint alert records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_alert import MdeAlert
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.mde_shared import (
    MDE_ALERT_CATEGORIES,
    MDE_ALERT_TITLES,
    MDE_DETECTION_SOURCES,
    MDE_INVESTIGATION_STATES,
    MDE_SEVERITY_LEVELS,
    MDE_THREAT_NAMES,
    mde_guid,
)
from repository.mde_alert_repo import mde_alert_repo

_STATUS_CHOICES: list[str] = (
    ["New"] * 5
    + ["InProgress"] * 3
    + ["Resolved"] * 2
)
"""Weighted alert statuses: 50% New, 30% InProgress, 20% Resolved."""

_MALWARE_CATEGORIES: frozenset[str] = frozenset({
    "Malware", "Ransomware", "UnwantedSoftware",
})

_EVIDENCE_ENTITY_TYPES: list[str] = ["File", "Process", "Ip", "User"]

_COMMENT_TEMPLATES: list[str] = [
    "Escalated to Tier 2 for further analysis.",
    "Initial triage complete -- awaiting sandbox results.",
    "False positive confirmed; closing alert.",
    "Correlated with incident from last week.",
    "Endpoint isolated pending remediation.",
    "Malware sample submitted for deep analysis.",
]


def seed_mde_alerts(fake: Faker, machine_ids: list[str]) -> list[str]:
    """Generate approximately 40 MDE alert records.

    Each alert is linked to a random machine from the provided list.
    Alerts include realistic evidence items and optional pre-existing
    comments.

    Args:
        fake: Shared Faker instance (seeded externally).
        machine_ids: List of ``machineId`` strings to associate alerts with.

    Returns:
        List of ``alertId`` strings.
    """
    alert_ids: list[str] = []
    alert_count = 40

    for _ in range(alert_count):
        alert_id = mde_guid()
        alert_ids.append(alert_id)

        machine_id = random.choice(machine_ids)
        category = random.choice(MDE_ALERT_CATEGORIES)
        status = random.choice(_STATUS_CHOICES)
        severity = random.choice(MDE_SEVERITY_LEVELS)
        title = random.choice(MDE_ALERT_TITLES)

        # Threat name only for malware-related categories
        threat_name = ""
        threat_family = ""
        if category in _MALWARE_CATEGORIES:
            threat_name = random.choice(MDE_THREAT_NAMES)
            # Extract family from threat name (e.g. "Trojan:Win32/Emotet.RPH!MTB" -> "Emotet")
            parts = threat_name.split("/")
            if len(parts) > 1:
                threat_family = parts[1].split(".")[0]

        # Timestamps
        creation_time = rand_ago(30)
        first_event = creation_time
        last_event = rand_ago(15)
        last_update = rand_ago(5)
        resolved_time = rand_ago(2) if status == "Resolved" else ""

        # Evidence items: 1-3
        evidence_count = random.randint(1, 3)
        evidence: list[dict] = []
        for _ in range(evidence_count):
            entity_type = random.choice(_EVIDENCE_ENTITY_TYPES)
            item: dict = {"entityType": entity_type}
            if entity_type == "File":
                item["sha256"] = fake.sha256()
                item["fileName"] = fake.file_name(extension="exe")
                item["filePath"] = f"C:\\Users\\{fake.user_name()}\\AppData\\Local\\Temp"
            elif entity_type == "Process":
                item["processId"] = random.randint(1000, 65535)
                item["fileName"] = random.choice([
                    "powershell.exe", "cmd.exe", "rundll32.exe",
                    "svchost.exe", "python.exe",
                ])
            elif entity_type == "Ip":
                item["ipAddress"] = fake.ipv4_public()
            elif entity_type == "User":
                item["accountName"] = fake.user_name()
                item["domainName"] = "ACMECORP"
            evidence.append(item)

        # Comments: 0-2
        comment_count = random.randint(0, 2)
        comments: list[dict] = []
        for _ in range(comment_count):
            comments.append({
                "comment": random.choice(_COMMENT_TEMPLATES),
                "createdBy": fake.email(),
                "createdTime": rand_ago(10),
            })

        # Classification / determination for resolved alerts
        classification = ""
        determination = ""
        assigned_to = ""
        if status in ("InProgress", "Resolved"):
            assigned_to = fake.email()
        if status == "Resolved":
            classification = random.choice([
                "TruePositive", "FalsePositive", "BenignPositive",
            ])
            determination = random.choice([
                "Malware", "NotMalware", "Phishing", "Other",
            ])

        mde_alert_repo.save(MdeAlert(
            alertId=alert_id,
            title=title,
            description=f"Alert generated: {title}. Investigate the affected endpoint for signs of compromise.",
            severity=severity,
            status=status,
            classification=classification,
            determination=determination,
            assignedTo=assigned_to,
            machineId=machine_id,
            incidentId=random.randint(1, 100),
            investigationId=random.randint(1, 50),
            investigationState=random.choice(MDE_INVESTIGATION_STATES),
            category=category,
            detectionSource=random.choice(MDE_DETECTION_SOURCES),
            threatName=threat_name,
            threatFamilyName=threat_family,
            alertCreationTime=creation_time,
            lastUpdateTime=last_update,
            resolvedTime=resolved_time,
            firstEventTime=first_event,
            lastEventTime=last_event,
            comments=comments,
            evidence=evidence,
        ))

    return alert_ids
