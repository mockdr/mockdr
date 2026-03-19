"""MDE indicators seeder -- generates threat indicator (IoC) records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_indicator import MdeIndicator
from infrastructure.seeders._shared import ago, rand_ago
from infrastructure.seeders.mde_shared import MDE_SEVERITY_LEVELS, mde_guid
from repository.mde_indicator_repo import mde_indicator_repo

_INDICATOR_ACTIONS: list[str] = [
    "Alert", "AlertAndBlock", "Allowed", "Block", "Warn",
]

_INDICATOR_TITLES: list[str] = [
    "Known C2 infrastructure",
    "Phishing domain",
    "Malware hash - Emotet variant",
    "Ransomware payload hash",
    "Suspicious IP - brute force origin",
    "Known malvertising domain",
    "Credential harvesting endpoint",
    "Cobalt Strike beacon hash",
    "TOR exit node",
    "Malicious document hash",
]

_DOMAIN_NAMES: list[str] = [
    "evil-payload.test", "c2-beacon.test", "phish-login.test",
    "malware-drop.test", "exfil-data.test",
]

_IP_PREFIXES: list[str] = [
    "185.220.101.", "91.219.236.", "45.155.205.",
    "194.26.192.", "23.129.64.",
]


def seed_mde_indicators(fake: Faker) -> None:
    """Generate approximately 20 MDE threat indicators.

    Creates a mix of FileSha256, IpAddress, and DomainName indicator types
    with realistic metadata.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    indicator_count = 20

    for i in range(indicator_count):
        indicator_id = mde_guid()

        # Rotate indicator types
        type_index = i % 3
        if type_index == 0:
            indicator_type = "FileSha256"
            indicator_value = fake.sha256()
        elif type_index == 1:
            indicator_type = "IpAddress"
            indicator_value = random.choice(_IP_PREFIXES) + str(random.randint(1, 254))
        else:
            indicator_type = "DomainName"
            indicator_value = random.choice(_DOMAIN_NAMES)

        title = random.choice(_INDICATOR_TITLES)
        creation_time = rand_ago(60)

        mde_indicator_repo.save(MdeIndicator(
            indicatorId=indicator_id,
            indicatorValue=indicator_value,
            indicatorType=indicator_type,
            action=random.choice(_INDICATOR_ACTIONS),
            severity=random.choice(MDE_SEVERITY_LEVELS),
            title=title,
            description=f"Threat indicator: {title}. Type: {indicator_type}.",
            recommendedActions="Investigate and block if confirmed malicious.",
            rbacGroupNames=[],
            generateAlert=random.choice([True, True, False]),
            createdBy=fake.email(),
            createdByDisplayName=fake.name(),
            createdBySource=random.choice(["User", "User", "WindowsDefenderAtp"]),
            creationTimeDateTimeUtc=creation_time,
            expirationTime=ago(-random.randint(30, 180)),  # future date
            lastUpdatedBy=fake.email(),
            lastUpdateTime=rand_ago(10),
        ))
