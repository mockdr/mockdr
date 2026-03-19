"""MDE vulnerabilities seeder -- generates TVM vulnerability (CVE) records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_vulnerability import MdeVulnerability
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.mde_shared import MDE_CVE_IDS
from repository.mde_vulnerability_repo import mde_vulnerability_repo

_CVE_DESCRIPTIONS: dict[str, str] = {
    "CVE-2024-21412": "Internet Shortcut Files Security Feature Bypass Vulnerability",
    "CVE-2024-30051": "Windows DWM Core Library Elevation of Privilege Vulnerability",
    "CVE-2024-38063": "Windows TCP/IP Remote Code Execution Vulnerability",
    "CVE-2024-43451": "NTLM Hash Disclosure Spoofing Vulnerability",
    "CVE-2024-49138": "Windows Common Log File System Driver Elevation of Privilege Vulnerability",
    "CVE-2023-36802": "Microsoft Streaming Service Proxy Elevation of Privilege Vulnerability",
    "CVE-2023-44487": "HTTP/2 Rapid Reset Attack Vulnerability",
    "CVE-2023-36884": "Windows Search Remote Code Execution Vulnerability",
    "CVE-2023-23397": "Microsoft Outlook Elevation of Privilege Vulnerability",
    "CVE-2023-21823": "Windows Graphics Component Remote Code Execution Vulnerability",
    "CVE-2022-41040": "Microsoft Exchange Server Elevation of Privilege Vulnerability",
    "CVE-2022-30190": "Microsoft Windows Support Diagnostic Tool (MSDT) Remote Code Execution Vulnerability",
    "CVE-2022-26134": "Atlassian Confluence Server and Data Center Remote Code Execution Vulnerability",
    "CVE-2021-44228": "Apache Log4j2 Remote Code Execution Vulnerability",
    "CVE-2021-34527": "Windows Print Spooler Remote Code Execution Vulnerability",
}

_SEVERITY_CVSS_MAP: list[tuple[str, float, float]] = [
    ("Critical", 9.0, 10.0),
    ("High", 7.0, 8.9),
    ("Medium", 4.0, 6.9),
    ("Low", 0.1, 3.9),
]

_SEVERITY_WEIGHTS: list[str] = [
    "Critical", "Critical",
    "High", "High", "High",
    "Medium", "Medium", "Medium", "Medium",
    "Low",
]


def seed_mde_vulnerabilities(fake: Faker) -> None:
    """Generate approximately 15 MDE TVM vulnerability (CVE) records.

    Uses the predefined ``MDE_CVE_IDS`` list with realistic descriptions
    and CVSS scores aligned to severity levels.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    for cve_id in MDE_CVE_IDS:
        severity = random.choice(_SEVERITY_WEIGHTS)

        # Pick CVSS range matching severity
        cvss_min, cvss_max = 4.0, 6.9
        for sev_name, s_min, s_max in _SEVERITY_CVSS_MAP:
            if sev_name == severity:
                cvss_min, cvss_max = s_min, s_max
                break

        cvss_score = round(random.uniform(cvss_min, cvss_max), 1)
        description = _CVE_DESCRIPTIONS.get(cve_id, f"Vulnerability {cve_id}")

        mde_vulnerability_repo.save(MdeVulnerability(
            vulnerabilityId=cve_id,
            name=cve_id,
            description=description,
            severity=severity,
            cvssV3=cvss_score,
            exposedMachines=random.randint(0, 20),
            publicExploit=random.choice([True, True, False]),
            publishedOn=rand_ago(365),
            updatedOn=rand_ago(30),
        ))
