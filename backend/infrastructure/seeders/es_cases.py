"""Elastic Security cases seeder."""
from __future__ import annotations

import random

from faker import Faker

from domain.es_case import EsCase
from domain.es_case_comment import EsCaseComment
from infrastructure.seeders._shared import rand_after, rand_ago
from infrastructure.seeders.es_shared import ES_CASE_TAGS, es_uuid
from repository.es_case_comment_repo import es_case_comment_repo
from repository.es_case_repo import es_case_repo
from utils.es_case_serde import KIBANA_USER

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

#: The user every seeded case is filed by. `utils.es_case_serde` already
#: carries the shape measured against 8.15 — `elastic` is Elasticsearch's
#: reserved superuser and has no profile, so the real cluster answers
#: `"full_name": null, "email": null` for it, and so does Kibana wherever it
#: names a user. Seeding an invented "Elastic Admin" here put those strings
#: into every case's `created_by`, `updated_by` and `closed_by`, and out
#: through `/api/cases/reporters`, where the live comparison caught them.
_MOCK_USER = KIBANA_USER


def seed_es_cases(fake: Faker, alert_ids: list[str]) -> None:
    """Generate 8 Elastic Security cases with comments.

    Each case includes 2-5 comments. Status distribution: 50% open,
    30% in-progress, 20% closed.

    Args:
        fake:      Shared Faker instance (seeded externally).
        alert_ids: Alert IDs to attach cases to; ``total_alerts`` counts the
                   alerts a case actually references.
    """
    for i, title in enumerate(_CASE_TITLES):
        case_id = es_uuid()
        status = random.choice(_STATUS_WEIGHTS)
        severity = random.choice(_SEVERITY_LEVELS)
        tags = random.sample(ES_CASE_TAGS, random.randint(1, 3))
        created_at = rand_ago(random.randint(7, 60))
        # Attach real alerts rather than inventing a count: the parameter was
        # passed in and discarded, so total_alerts described nothing.
        pool = alert_ids or []
        case_alert_ids = (
            random.sample(pool, min(len(pool), random.randint(1, 5))) if pool else []
        )
        num_alerts = len(case_alert_ids)
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
            updated_at=rand_after(created_at),
            updated_by=_MOCK_USER,
            closed_at=closed_at,
            closed_by=closed_by,
            version=f"Wz{i + 1}sMV0=",
            total_comment=num_comments,
            total_alerts=num_alerts,
            alert_ids=case_alert_ids,
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
                created_at=(comment_created := rand_ago(random.randint(0, 30))),
                created_by=_MOCK_USER,
                updated_at=rand_after(comment_created),
                updated_by=_MOCK_USER,
                version=f"Wz{random.randint(1, 50)}sMV0=",
            ))
