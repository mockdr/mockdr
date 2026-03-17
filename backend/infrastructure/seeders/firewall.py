"""Firewall rules seeder — seeds eight firewall rule records."""
import random

from faker import Faker

from domain.firewall_rule import FirewallRule
from infrastructure.seeders._shared import rand_ago
from repository.firewall_repo import firewall_repo
from utils.id_gen import new_id


def seed_firewall_rules(
    fake: Faker,
    site_ids: list[str],
    user_ids: list[str],
) -> None:
    """Create eight firewall rule records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        site_ids: Pool of site IDs for scope assignment.
        user_ids: Pool of user IDs; the first entry is used as creator.
    """
    admin_user_id = user_ids[0]

    for i in range(8):
        fid = new_id()
        has_port = random.random() > 0.4
        has_remote_ip = random.random() > 0.5
        fw_os = random.choice(["windows", "windows", "macos", "linux"])
        fw_site_id = random.choice(site_ids)
        firewall_repo.save(FirewallRule(
            id=fid,
            name=f"Rule-{i + 1:03d}-{fake.word().upper()}",
            description=fake.sentence(nb_words=5),
            status=random.choice(["Enabled", "Enabled", "Disabled"]),
            action=random.choice(["Allow", "Block"]),
            direction=random.choice(["inbound", "outbound", "any"]),
            protocol=random.choice(["TCP", "UDP", "ICMP", None]),
            osType=fw_os,
            osTypes=[fw_os],
            createdAt=rand_ago(90),
            updatedAt=rand_ago(30),
            order=i + 1,
            ruleCategory="firewall",
            scope="site",
            scopeId=fw_site_id,
            editable=True,
            tag=fake.sentence(nb_words=4),
            tagIds=[],
            tagNames=[],
            tags=[],
            creator="Admin User",
            creatorId=admin_user_id,
            localPort=(
                {"type": "specific", "values": [str(random.randint(1, 65535))]}
                if has_port else {"type": "any", "values": []}
            ),
            remotePort=(
                {"type": "specific", "values": [str(random.randint(1, 65535))]}
                if has_port else {"type": "any", "values": []}
            ),
            localHost={"type": "any", "values": []},
            remoteHost={"type": "any", "values": []},
            remoteHosts=(
                [{"type": "addresses", "values": [fake.ipv4_public()]}]
                if has_remote_ip else [{"type": "any", "values": []}]
            ),
            application={"type": "any", "values": []},
            location={"type": "all", "values": []},
            # internal
            siteId=fw_site_id,
        ))
