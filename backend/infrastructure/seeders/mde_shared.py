"""MDE-specific reference data and helper functions.

Constants and pure helpers shared across all MDE domain seeders.
No repository imports -- this module must remain free of side effects.
"""
from __future__ import annotations

import random

MDE_TENANT_ID: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
"""Mock Azure AD tenant ID."""

MDE_AGENT_VERSIONS: list[str] = [
    "10.8910.23012.1022",
    "10.8810.22621.2506",
    "10.8750.22060.1010",
    "10.8670.21520.1015",
    "10.8560.20890.1008",
]
"""Realistic MDE Sense agent version strings."""

MDE_DETECTION_SOURCES: list[str] = [
    "WindowsDefenderAtp",
    "WindowsDefenderAv",
    "CustomDetection",
    "AutomatedInvestigation",
    "ThirdPartyApis",
]

MDE_ALERT_CATEGORIES: list[str] = [
    "Malware",
    "SuspiciousActivity",
    "UnwantedSoftware",
    "Ransomware",
    "CredentialAccess",
    "Exploit",
    "LateralMovement",
    "CommandAndControl",
    "GeneralInformation",
]

MDE_RISK_SCORES: list[str | None] = (
    [None] * 5
    + ["Low"] * 2
    + ["Medium"] * 2
    + ["High"] * 1
)
"""Weighted risk scores: 50% None, 20% Low, 20% Medium, 10% High."""

MDE_EXPOSURE_LEVELS: list[str | None] = (
    [None] * 4
    + ["Low"] * 3
    + ["Medium"] * 2
    + ["High"] * 1
)
"""Weighted exposure levels: 40% None, 30% Low, 20% Medium, 10% High."""

MDE_HEALTH_STATUSES: list[str] = (
    ["Active"] * 17
    + ["Inactive"] * 2
    + ["ImpairedCommunication"] * 1
)
"""Weighted health statuses: 85% Active, 10% Inactive, 5% ImpairedCommunication."""

MDE_MACHINE_ACTION_TYPES: list[str] = [
    "Isolate",
    "Unisolate",
    "RunAntiVirusScan",
    "CollectInvestigationPackage",
    "RestrictCodeExecution",
    "UnrestrictCodeExecution",
    "Offboard",
]

MDE_INVESTIGATION_STATES: list[str] = (
    ["SuccessfullyRemediated"] * 4
    + ["Benign"] * 3
    + ["Running"] * 2
    + ["PartiallyRemediated"] * 2
    + ["TerminatedByUser"] * 1
    + ["Failed"] * 1
    + ["Queued"] * 1
)
"""Weighted investigation states."""

MDE_ALERT_TITLES: list[str] = [
    "Suspicious PowerShell command line",
    "Malware was detected",
    "Possible exploitation of CVE-2024-21412",
    "Ransomware behavior detected on endpoint",
    "Credential dumping tool detected",
    "Suspicious process injection",
    "Anomalous token creation from unusual location",
    "Encoded PowerShell script execution",
    "Lateral movement using stolen credentials",
    "Suspicious DLL side-loading detected",
    "Fileless malware behavior observed",
    "Suspicious scheduled task creation",
    "Suspicious network connection to known C2",
    "Unusual file modification in system directory",
    "Brute-force attack detected on RDP",
]

MDE_THREAT_NAMES: list[str] = [
    "Trojan:Win32/Emotet.RPH!MTB",
    "Ransom:Win32/LockBit.PA!MTB",
    "Backdoor:Win32/CobaltStrike.D!MTB",
    "TrojanSpy:Win32/AgentTesla.SRN!MTB",
    "Trojan:Win32/Qakbot.PAA!MTB",
    "Exploit:Win32/CVE-2024-21412",
    "HackTool:Win64/Mimikatz.D",
    "Ransom:Win32/BlackCat.AA!MTB",
    "TrojanDownloader:Win32/IcedId.RK!MTB",
    "Trojan:Win32/RedLine.RPK!MTB",
]

MDE_SEVERITY_LEVELS: list[str] = [
    "Informational",
    "Low",
    "Medium",
    "Medium",
    "High",
    "High",
]
"""Weighted severity levels."""

MDE_CVE_IDS: list[str] = [
    "CVE-2024-21412",
    "CVE-2024-30051",
    "CVE-2024-38063",
    "CVE-2024-43451",
    "CVE-2024-49138",
    "CVE-2023-36802",
    "CVE-2023-44487",
    "CVE-2023-36884",
    "CVE-2023-23397",
    "CVE-2023-21823",
    "CVE-2022-41040",
    "CVE-2022-30190",
    "CVE-2022-26134",
    "CVE-2021-44228",
    "CVE-2021-34527",
]


def mde_guid() -> str:
    """Generate a deterministic UUID-style string using the seeded RNG.

    Produces a string in the standard 8-4-4-4-12 hexadecimal GUID format
    using ``random.randint`` so results are reproducible under a global
    ``random.seed(42)``.

    Returns:
        A lowercase GUID string, e.g. ``"a3f1b2c4-d5e6-7890-abcd-ef1234567890"``.
    """
    def _hex(n: int) -> str:
        return "".join(f"{random.randint(0, 15):x}" for _ in range(n))

    return f"{_hex(8)}-{_hex(4)}-{_hex(4)}-{_hex(4)}-{_hex(12)}"
