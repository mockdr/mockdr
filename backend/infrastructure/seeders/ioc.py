"""IoC seeder — seeds twenty threat-intelligence indicator records."""
import random
from collections.abc import Callable

from faker import Faker

from domain.ioc import IOC
from infrastructure.seeders._shared import MALWARE_NAMES, ago, rand_ago
from repository.ioc_repo import ioc_repo
from utils.id_gen import new_id

_IOC_TYPES: list[str] = ["IPV4", "IPV6", "DNS", "URL", "SHA1", "SHA256", "MD5"]


def seed_iocs(fake: Faker) -> None:
    """Create twenty IoC records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
    """
    value_map: dict[str, Callable[[], str]] = {
        "IPV4":   fake.ipv4_public,
        "IPV6":   fake.ipv6,
        "DNS":    fake.domain_name,
        "URL":    fake.url,
        "SHA1":   fake.sha1,
        "SHA256": fake.sha256,
        "MD5":    fake.md5,
    }
    for _ in range(20):
        ioc_uuid = new_id()
        ioc_type = random.choice(_IOC_TYPES)
        ioc_repo.save(IOC(
            uuid=ioc_uuid,
            type=ioc_type,
            value=value_map[ioc_type](),
            name=f"{random.choice(MALWARE_NAMES)} Indicator",
            description=f"Threat Intel: {random.choice(MALWARE_NAMES)}",
            source=random.choice(["user", "OSINT", "internal", "vendor"]),
            validUntil=ago(days=-random.randint(7, 365)),
            creationTime=rand_ago(60),
            updatedAt=rand_ago(10),
            method="EQUALS",
        ))
