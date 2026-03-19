"""CrowdStrike IOC seeder — creates custom indicator of compromise records."""
from __future__ import annotations

import hashlib
import random

from faker import Faker

from domain.cs_ioc import CsIoc
from infrastructure.seeders._shared import ago, rand_ago
from infrastructure.seeders.cs_shared import (
    CS_IOC_ACTIONS,
    CS_IOC_SEVERITIES,
    CS_IOC_TYPES,
)
from repository.cs_ioc_repo import cs_ioc_repo
from utils.id_gen import new_id

_COUNT: int = 20

_IOC_DESCRIPTIONS: list[str] = [
    "Known C2 infrastructure",
    "Malware hash from threat intel feed",
    "Phishing domain indicator",
    "Ransomware file hash",
    "Suspicious IP from honeypot",
    "Credential stealer hash",
    "APT-related domain",
    "Cryptominer indicator",
    "Botnet C2 node",
    "Supply chain compromise artifact",
]

_PLATFORMS_BY_TYPE: dict[str, list[str]] = {
    "sha256": ["windows", "mac", "linux"],
    "md5": ["windows", "mac", "linux"],
    "domain": ["windows", "mac", "linux"],
    "ipv4": ["windows", "mac", "linux"],
    "ipv6": ["windows", "mac", "linux"],
}


def _generate_ioc_value(fake: Faker, ioc_type: str) -> str:
    """Generate a realistic IOC value for the given indicator type.

    Args:
        fake: Shared Faker instance.
        ioc_type: One of sha256, md5, domain, ipv4, ipv6.

    Returns:
        IOC value string matching the type.
    """
    if ioc_type == "sha256":
        return hashlib.sha256(fake.binary(length=32)).hexdigest()
    if ioc_type == "md5":
        return hashlib.md5(fake.binary(length=16), usedforsecurity=False).hexdigest()  # noqa: S324
    if ioc_type == "domain":
        return fake.domain_name()
    if ioc_type == "ipv4":
        return fake.ipv4_public()
    if ioc_type == "ipv6":
        return fake.ipv6()
    return fake.sha256()


def seed_cs_iocs(fake: Faker) -> list[str]:
    """Create CrowdStrike custom IOC records.

    Generates ``_COUNT`` IOCs across all indicator types with realistic
    values and metadata.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of IOC ID strings.
    """
    ioc_ids: list[str] = []
    creator_uid = "cs-mock-admin-client"

    for _ in range(_COUNT):
        ioc_id = new_id()
        ioc_ids.append(ioc_id)

        ioc_type = random.choice(CS_IOC_TYPES)
        value = _generate_ioc_value(fake, ioc_type)
        action = random.choice(CS_IOC_ACTIONS)
        severity = random.choice(CS_IOC_SEVERITIES)
        description = random.choice(_IOC_DESCRIPTIONS)
        platforms = _PLATFORMS_BY_TYPE.get(ioc_type, ["windows"])

        created_ts = rand_ago(60)
        modified_ts = rand_ago(10)

        # Some IOCs have expiration (future date), most do not
        has_expiration = random.random() < 0.3
        expiration = ago(days=-random.randint(7, 90)) if has_expiration else ""
        expired = False

        tag_count = random.randint(0, 2)
        tags = random.sample(
            ["threat_intel", "automated", "manual", "high_confidence", "apt"],
            tag_count,
        )

        cs_ioc_repo.save(CsIoc(
            id=ioc_id,
            type=ioc_type,
            value=value,
            source=random.choice(["api_client", "fql_query", "cortex_xsoar", "manual"]),
            action=action,
            severity=severity,
            description=description,
            platforms=platforms,
            tags=tags,
            applied_globally=random.random() > 0.2,
            host_groups=[],
            expiration=expiration,
            expired=expired,
            deleted=False,
            mobile_action="no_action",
            created_on=created_ts,
            created_by=creator_uid,
            modified_on=modified_ts,
            modified_by=creator_uid,
            from_parent=False,
            metadata={},
        ))

    return ioc_ids
