"""XDR IOCs seeder -- generates a mix of indicator types."""
from __future__ import annotations

import random

from faker import Faker

from domain.xdr_ioc import XdrIoc
from infrastructure.seeders.xdr_shared import XDR_SEVERITIES, rand_epoch_ms, xdr_id
from repository.xdr_ioc_repo import xdr_ioc_repo

_HASH_IOCS: list[str] = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e",
    "6dcd4ce23d88e2ee9568ba546c007c63d9131c1b",
    "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f",
]

_IP_IOCS: list[str] = [
    "185.220.101.42",
    "91.219.237.108",
    "23.129.64.130",
    "198.98.56.128",
    "45.33.32.156",
    "104.248.39.107",
]

_DOMAIN_IOCS: list[str] = [
    "evil-payload.badactor.com",
    "c2-server.malware-domain.net",
    "exfil-data.darkweb.org",
    "phishing-site.fake-bank.com",
    "crypto-miner.botnet.io",
    "backdoor.apt-group.net",
]

_REPUTATIONS: list[str] = [
    "malicious", "malicious", "malicious",
    "suspicious", "suspicious",
    "unknown",
]


def seed_xdr_iocs(fake: Faker) -> None:
    """Seed ~20 XDR IOC records (mix of hash, IP, domain).

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    # Hash IOCs
    for h in _HASH_IOCS:
        xdr_ioc_repo.save(XdrIoc(
            ioc_id=xdr_id("IOC"),
            indicator=h,
            type="hash",
            severity=random.choice(XDR_SEVERITIES),
            reputation=random.choice(_REPUTATIONS),
            status="enabled",
            expiration_date=rand_epoch_ms(-90) if random.random() < 0.3 else None,
            comment="Hash IOC added by threat intel feed",
            vendors=[{"vendor_name": "Cortex XDR", "reliability": "A"}],
        ))

    # IP IOCs
    for ip in _IP_IOCS:
        xdr_ioc_repo.save(XdrIoc(
            ioc_id=xdr_id("IOC"),
            indicator=ip,
            type="ip",
            severity=random.choice(XDR_SEVERITIES),
            reputation=random.choice(_REPUTATIONS),
            status="enabled",
            expiration_date=rand_epoch_ms(-30) if random.random() < 0.2 else None,
            comment="Suspicious IP from threat intel",
            vendors=[{"vendor_name": "AutoFocus", "reliability": "B"}],
        ))

    # Domain IOCs
    for domain in _DOMAIN_IOCS:
        xdr_ioc_repo.save(XdrIoc(
            ioc_id=xdr_id("IOC"),
            indicator=domain,
            type="domain_name",
            severity=random.choice(XDR_SEVERITIES),
            reputation=random.choice(_REPUTATIONS),
            status=random.choice(["enabled", "enabled", "disabled"]),
            expiration_date=None,
            comment="Malicious domain from OSINT feed",
            vendors=[{"vendor_name": "Unit 42", "reliability": "A"}],
        ))
