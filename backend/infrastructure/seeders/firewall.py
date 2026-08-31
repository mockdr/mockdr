"""Firewall rules seeder — seeds eight firewall rule records."""
import random

from faker import Faker

from domain.firewall_rule import FirewallRule
from infrastructure.safe_net import doc_ipv4
from infrastructure.seeders._shared import rand_after, rand_ago
from repository.firewall_repo import firewall_repo
from utils.id_gen import new_id

#: Tags a firewall rule is scoped by, when it is scoped by one.
_TAG_NAMES: list[str] = ["Servers", "Workstations", "Contractors", "Executives"]


def _a_tag_id(index: int) -> str:
    """A tag id for every other rule, so both states are always seeded."""
    from repository.store import store  # noqa: PLC0415 - avoids a cycle

    if index % 2:
        return ""
    tags = list(store.get_all("tags"))
    return str(getattr(tags[index % len(tags)], "id", "")) if tags else ""


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
            createdAt=(created := rand_ago(90)),
            updatedAt=rand_after(created),
            order=i + 1,
            ruleCategory="firewall",
            scope="site",
            scopeId=fw_site_id,
            editable=True,
            tag=fake.sentence(nb_words=4),
            # A rule scoped by tag names the tags. Both were empty on every
            # rule, so the two documented filters over them matched none.
            tagIds=[tag_id] if (tag_id := _a_tag_id(i)) else [],
            tagNames=[_TAG_NAMES[i % len(_TAG_NAMES)]] if tag_id else [],
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
                [{"type": "addresses", "values": [doc_ipv4()]}]
                if has_remote_ip else [{"type": "any", "values": []}]
            ),
            application={"type": "any", "values": []},
            location={"type": "all", "values": []},
            # internal
            siteId=fw_site_id,
        ))
