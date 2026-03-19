"""CrowdStrike cases seeder — creates mock investigation/support cases."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_case import CsCase
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import CS_CID
from repository.cs_case_repo import cs_case_repo

_TITLES: list[str] = [
    "Ransomware Investigation - Finance Dept",
    "Phishing Campaign Analysis",
    "Lateral Movement Alert Triage",
    "Suspicious PowerShell Activity",
    "Credential Harvesting Incident",
    "Supply Chain Compromise Review",
    "Insider Threat Investigation",
    "Malware Outbreak Containment",
]

_TAGS: list[str] = [
    "high-priority", "ransomware", "phishing", "apt", "insider-threat",
    "malware", "incident-response", "threat-hunting",
]


def seed_cs_cases(fake: Faker, cs_detection_ids: list[str]) -> None:
    """Create mock CrowdStrike cases.

    Args:
        fake:             Shared Faker instance (seeded externally).
        cs_detection_ids: Detection IDs to reference in case bodies.
    """
    for i, title in enumerate(_TITLES):
        case_id = str(fake.uuid4())

        # Attach 1-3 detections to each case
        det_sample = random.sample(
            cs_detection_ids, min(random.randint(1, 3), len(cs_detection_ids))
        )
        detections = [{"id": d} for d in det_sample]

        tag_count = random.randint(1, 3)
        tags = random.sample(_TAGS, tag_count)

        cs_case_repo.save(CsCase(
            id=case_id,
            cid=CS_CID,
            title=title,
            body=f"Investigation case for: {title}. "
                 f"Initial detection triggered on {rand_ago(15)}.",
            detections=detections,
            type="standard" if i % 3 != 0 else "escalation",
            status=random.choice(["open"] * 5 + ["closed", "reopened"]),
            assigner={"uid": f"analyst{i}@acmecorp.internal", "name": fake.name()},
            assignee={"uid": f"responder{i}@acmecorp.internal", "name": fake.name()},
            tags=tags,
            fine_score=random.randint(0, 100),
            created_time=rand_ago(30),
            last_modified_time=rand_ago(3),
        ))
