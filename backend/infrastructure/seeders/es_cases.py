"""Elastic Security cases seeder."""
from __future__ import annotations

import random

from faker import Faker

from domain.es_case import EsCase
from domain.es_case_comment import EsCaseComment
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.es_shared import ES_CASE_TAGS, es_uuid
from repository.es_case_comment_repo import es_case_comment_repo
from repository.es_case_repo import es_case_repo

_STATUS_WEIGHTS: list[str] = (
    ["open"] * 10
    + ["in-progress"] * 6
    + ["closed"] * 4
)

_SEVERITY_LEVELS: list[str] = ["low", "medium", "high", "critical"]

_CASE_TITLES: list[str] = [
    "Ransomware Incident - Finance Department",
    "Phishing Campaign Targeting Executives",
    "Suspicious Lateral Movement Detected",
    "Credential Theft Investigation",
    "Malware Outbreak on Server Cluster",
    "APT Activity - Supply Chain Compromise",
    "Insider Threat - Data Exfiltration",
    "Brute Force Attack on VPN Gateway",
]

_COMMENT_TEMPLATES: list[str] = [
    "Initial triage completed. Escalating to Tier 2 for further investigation.",
    "Confirmed malicious activity. Isolating affected endpoints.",
    "IOCs extracted and added to blocklist. Monitoring for additional hits.",
    "Forensic image captured from affected workstation.",
    "Root cause identified: phishing email with malicious attachment.",
    "Containment actions completed. Beginning remediation phase.",
    "Affected user credentials rotated. Monitoring for reuse.",
    "All endpoints scanned. No additional compromise detected.",
    "Case handed off to legal team for review.",
    "Closing case. All remediation steps verified and documented.",
    "Updated timeline with new evidence from network logs.",
    "Contacted affected user for interview. Awaiting response.",
]

_MOCK_USER: dict[str, str] = {
    "email": "elastic-admin@acmecorp.internal",
    "full_name": "Elastic Admin",
    "username": "elastic",
}


def seed_es_cases(fake: Faker, alert_ids: list[str]) -> None:
    """Generate 8 Elastic Security cases with comments.

    Each case includes 2-5 comments. Status distribution: 50% open,
    30% in-progress, 20% closed.

    Args:
        fake:      Shared Faker instance (seeded externally).
        alert_ids: List of alert ID strings (used for total_alerts count).
    """
    for i, title in enumerate(_CASE_TITLES):
        case_id = es_uuid()
        status = random.choice(_STATUS_WEIGHTS)
        severity = random.choice(_SEVERITY_LEVELS)
        tags = random.sample(ES_CASE_TAGS, random.randint(1, 3))
        created_at = rand_ago(random.randint(7, 60))
        num_alerts = random.randint(1, 5)
        num_comments = random.randint(2, 5)

        closed_at = None
        closed_by = None
        if status == "closed":
            closed_at = rand_ago(random.randint(0, 6))
            closed_by = _MOCK_USER

        es_case_repo.save(EsCase(
            id=case_id,
            title=title,
            description=f"Investigation for: {title.lower()}.",
            status=status,
            severity=severity,
            tags=tags,
            owner="securitySolution",
            assignees=[{"uid": "elastic-admin-uid"}],
            created_at=created_at,
            created_by=_MOCK_USER,
            updated_at=rand_ago(random.randint(0, 6)),
            updated_by=_MOCK_USER,
            closed_at=closed_at,
            closed_by=closed_by,
            version=f"Wz{i + 1}sMV0=",
            total_comment=num_comments,
            total_alerts=num_alerts,
        ))

        # Generate comments
        available_comments = random.sample(
            _COMMENT_TEMPLATES,
            min(num_comments, len(_COMMENT_TEMPLATES)),
        )
        for comment_text in available_comments:
            comment_id = es_uuid()
            es_case_comment_repo.save(EsCaseComment(
                id=comment_id,
                case_id=case_id,
                comment=comment_text,
                type="user",
                created_at=rand_ago(random.randint(0, 30)),
                created_by=_MOCK_USER,
                updated_at=rand_ago(random.randint(0, 7)),
                updated_by=_MOCK_USER,
                version=f"Wz{random.randint(1, 50)}sMV0=",
            ))
