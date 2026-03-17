"""MDE software seeder -- generates Threat & Vulnerability Management software entries."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_software import MdeSoftware
from infrastructure.seeders._shared import APP_CATALOG, EDR_VERSION_POOL
from repository.mde_software_repo import mde_software_repo

# Additional MDE-specific software beyond the shared APP_CATALOG
_EXTRA_SOFTWARE: list[tuple[str, str, str]] = [
    ("Windows 10", "22H2", "Microsoft Corporation"),
    ("Windows 11", "23H2", "Microsoft Corporation"),
    ("Windows Server 2022", "21H2", "Microsoft Corporation"),
    (".NET Framework", "4.8.1", "Microsoft Corporation"),
    ("OpenSSL", "3.2.1", "OpenSSL Project"),
]

# Software names that are known EOL or carry high vulnerability counts
_HIGH_RISK_SOFTWARE: set[str] = {
    "Adobe Flash Player", "Java Runtime Environment", "Microsoft Silverlight",
    "Windows 7 Embedded", "Internet Explorer", "Python 2.7", "Apache Log4j",
    "Mimikatz", "Cobalt Strike", "PsExec",
    "qBittorrent", "uTorrent", "BitTorrent",
}

# Software names flagged as having public exploits
_PUBLIC_EXPLOIT_SOFTWARE: set[str] = {
    "Adobe Flash Player", "Apache Log4j", "Java Runtime Environment",
    "Mimikatz", "Cobalt Strike", "Internet Explorer",
}

# Software names that trigger active alerts
_ACTIVE_ALERT_SOFTWARE: set[str] = {
    "Mimikatz", "Cobalt Strike", "qBittorrent", "uTorrent", "BitTorrent",
}


def _make_software_id(vendor: str, name: str) -> str:
    """Build an MDE-style software ID from vendor and product name.

    Args:
        vendor: Software vendor/publisher name.
        name: Software product name.

    Returns:
        Normalised ``"vendor-_-product"`` string.
    """
    v = vendor.lower().replace(" ", "_").replace(",", "").replace(".", "")
    n = name.lower().replace(" ", "_").replace(",", "").replace(".", "")
    return f"{v}-_-{n}"


def seed_mde_software(fake: Faker, machine_ids: list[str]) -> None:
    """Generate MDE TVM software entries from the shared app catalog.

    Includes standard corporate software, EDR agents, EOL applications,
    torrent clients, and dual-use security tools to support compliance
    checks and vulnerability management testing.

    Args:
        fake: Shared Faker instance (seeded externally).
        machine_ids: List of ``machineId`` strings (used for exposed machine counts).
    """
    all_software = list(APP_CATALOG) + _EXTRA_SOFTWARE

    # Add outdated/EOL EDR versions as separate TVM entries (compliance finding)
    for edr_name, versions in EDR_VERSION_POOL.items():
        edr_vendor = next(
            (v for n, _, v in APP_CATALOG if n == edr_name), "",
        )
        for ver, is_current in versions:
            if not is_current:
                all_software.append((f"{edr_name} (outdated)", ver, edr_vendor))

    for name, version, vendor in all_software:
        software_id = _make_software_id(vendor, name)

        is_high_risk = name in _HIGH_RISK_SOFTWARE
        has_public_exploit = name in _PUBLIC_EXPLOIT_SOFTWARE
        has_active_alert = name in _ACTIVE_ALERT_SOFTWARE

        weaknesses = random.randint(5, 25) if is_high_risk else random.randint(0, 8)
        exposed = random.randint(
            5, min(len(machine_ids), 30),
        ) if is_high_risk else random.randint(0, min(len(machine_ids), 15))

        mde_software_repo.save(MdeSoftware(
            softwareId=software_id,
            name=name,
            vendor=vendor,
            version=version,
            weaknesses=weaknesses,
            publicExploit=has_public_exploit or random.random() < 0.15,
            activeAlert=has_active_alert or random.random() < 0.1,
            exposedMachines=exposed,
            impactScore=round(random.uniform(6.0, 10.0), 1) if is_high_risk else round(random.uniform(0.0, 7.0), 1),
        ))
