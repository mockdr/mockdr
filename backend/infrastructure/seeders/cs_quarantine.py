"""CrowdStrike quarantine seeder — creates mock quarantined file records."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_quarantined_file import CsQuarantinedFile
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import CS_CID, cs_hex_id
from repository.cs_quarantine_repo import cs_quarantine_repo
from repository.store import store

_FILENAMES: list[str] = [
    "payload.exe", "dropper.dll", "ransomware.bin", "keylogger.sys",
    "miner.exe", "backdoor.dll", "trojan.exe", "worm.scr",
    "exploit.ps1", "stealer.exe",
]

_PATHS: list[str] = [
    "C:\\Users\\admin\\Downloads\\",
    "C:\\Windows\\Temp\\",
    "C:\\ProgramData\\",
    "/tmp/",  # nosec B108 — mock quarantine paths, not real temp usage
    "/var/tmp/",  # nosec B108
    "C:\\Users\\Public\\Documents\\",
]


def seed_cs_quarantine(fake: Faker, cs_host_ids: list[str]) -> None:
    """Create mock quarantined file records tied to CS hosts.

    Args:
        fake:        Shared Faker instance (seeded externally).
        cs_host_ids: List of CrowdStrike device IDs to associate files with.
    """
    count = min(15, len(cs_host_ids))

    for i in range(count):
        file_id = cs_hex_id()
        host_id = cs_host_ids[i % len(cs_host_ids)]
        filename = random.choice(_FILENAMES)
        path = random.choice(_PATHS)

        host = store.get("cs_hosts", host_id)
        hostname = host.hostname if host else "unknown"

        cs_quarantine_repo.save(CsQuarantinedFile(
            id=file_id,
            cid=CS_CID,
            aid=host_id,
            sha256=fake.sha256(),
            filename=filename,
            paths=f"{path}{filename}",
            state=random.choice(["quarantined"] * 8 + ["released", "deleted"]),
            hostname=hostname,
            username=f"ACMECORP\\{fake.user_name()}",
            date_created=rand_ago(30),
            date_updated=rand_ago(5),
            detect_ids=[cs_hex_id() for _ in range(random.randint(1, 3))],
        ))
