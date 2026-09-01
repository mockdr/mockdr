"""IoC seeder — seeds twenty threat-intelligence indicator records."""
import random
from collections.abc import Callable

from faker import Faker

from domain.ioc import IOC
from infrastructure.safe_net import doc_ipv4
from infrastructure.seeders._shared import MALWARE_NAMES, ago, rand_after, rand_ago
from repository.ioc_repo import ioc_repo
from repository.user_repo import user_repo
from utils.id_gen import new_id

_IOC_TYPES: list[str] = ["IPV4", "IPV6", "DNS", "URL", "SHA1", "SHA256", "MD5"]

#: What an indicator is filed under. Free-form in the swagger, so these are
#: the categories a threat-intelligence feed actually uses.
_CATEGORIES: list[str] = [
    "Malware", "Phishing", "Command and Control", "Ransomware", "Exfiltration",
]

#: Labels a feed attaches, and the campaigns and actors it names.
_LABELS: list[str] = ["high-confidence", "reviewed", "automated", "osint", "internal"]
_CAMPAIGNS: list[str] = [
    "Operation Sandstorm", "Silent Harvest", "Winter Vault", "Copper Tide",
]
#: `(actor, its type)`, kept together so a record's two members agree.
_THREAT_ACTORS: list[tuple[str, str]] = [
    ("APT29", "nation-state"),
    ("FIN7", "crime"),
    ("Lazarus Group", "nation-state"),
    ("TA505", "crime"),
    ("Scattered Spider", "crime"),
]


def seed_iocs(fake: Faker) -> None:
    """Create twenty IoC records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
    """
    value_map: dict[str, Callable[[], str]] = {
        "IPV4":   doc_ipv4,
        "IPV6":   fake.ipv6,
        "DNS":    fake.domain_name,
        "URL":    fake.url,
        "SHA1":   fake.sha1,
        "SHA256": fake.sha256,
        "MD5":    fake.md5,
    }
    # An indicator carries the intelligence it came with, and this record kept
    # almost none of it: eleven members the swagger declares were left unset,
    # so fourteen documented filters over them could match nothing and no test
    # could exercise one. `scripts/write_effect.py`'s sibling question — a
    # field the answer publishes that nothing fills — is what this closes.
    admin = next((u for u in user_repo.list_all() if u.fullName == "Admin User"), None)
    creator = admin.fullName if admin else "Admin User"
    batches = [f"batch-{new_id()[:12]}" for _ in range(3)]

    for index in range(20):
        ioc_uuid = new_id()
        ioc_type = random.choice(_IOC_TYPES)
        created = rand_ago(60)
        actor = random.choice(_THREAT_ACTORS)
        ioc_repo.save(IOC(
            uuid=ioc_uuid,
            type=ioc_type,
            value=value_map[ioc_type](),
            name=f"{random.choice(MALWARE_NAMES)} Indicator",
            description=f"Threat Intel: {random.choice(MALWARE_NAMES)}",
            source=random.choice(["user", "OSINT", "internal", "vendor"]),
            validUntil=ago(days=-random.randint(7, 365)),
            creationTime=created,
            # An indicator is uploaded when it is created or after it, never
            # before — the pair is drawn once rather than twice.
            uploadTime=rand_after(created, 5),
            # After the creation above, not drawn beside it.
            updatedAt=rand_after(created, 10),
            method="EQUALS",
            severity=random.choice([25, 50, 75, 100]),
            category=[random.choice(_CATEGORIES)],
            labels=random.sample(_LABELS, k=random.randint(1, 3)),
            malwareNames=[random.choice(MALWARE_NAMES)],
            campaignNames=[random.choice(_CAMPAIGNS)],
            threatActors=[actor[0]],
            threatActorTypes=[actor[1]],
            creator=creator,
            # Indicators arrive in uploads, so several share a batch.
            batchId=batches[index % len(batches)],
            externalId=f"TI-{1000 + index}",
        ))
