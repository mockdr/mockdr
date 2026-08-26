"""CrowdStrike cases seeder — creates mock investigation/support cases."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_case import CsCase
from domain.cs_user import CsUser
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


def _person(user: CsUser) -> dict:
    """A console user as the case entity names them (gofalcon `assigner`)."""
    return {
        "uid": user.uid,
        "uuid": user.uuid,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "display_name": f"{user.first_name} {user.last_name}",
        "email_address": user.uid,
    }


def seed_cs_cases(
    fake: Faker, cs_detection_ids: list[str], staff: list[CsUser],
) -> None:
    """Create mock CrowdStrike cases.

    Args:
        fake:             Shared Faker instance (seeded externally).
        cs_detection_ids: Detection IDs to reference in case bodies.
        staff:            The console users a case is assigned by and to.
    """
    for i, title in enumerate(_TITLES):
        case_id = str(fake.uuid4())
        assigner = staff[i % len(staff)]
        assignee = staff[(i + 1) % len(staff)]

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
            # `analyst0@`/`responder0@` were addresses this tenant did not
            # have, under names belonging to nobody at all. gofalcon's case
            # entity names the person by uid, uuid, both name parts, their
            # display name and their address.
            assigner=_person(assigner),
            assignee=_person(assignee),
            tags=tags,
            fine_score=random.randint(0, 100),
            created_time=rand_ago(30),
            last_modified_time=rand_ago(3),
        ))
