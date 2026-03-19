"""XDR-specific reference data and helper functions.

Constants and pure helpers shared across all XDR domain seeders.
No repository imports -- this module must remain free of side effects.
"""
from __future__ import annotations

import random
import time

XDR_TENANT_ID: str = "xdr-tenant-acmecorp-001"
"""Mock Cortex XDR tenant ID."""

XDR_SEVERITIES: list[str] = ["low", "medium", "medium", "high", "high", "critical"]
"""Weighted severity levels."""

XDR_INCIDENT_STATUSES: list[str] = [
    "new", "new", "new",
    "under_investigation", "under_investigation",
    "resolved_true_positive", "resolved_false_positive",
    "resolved_other",
]
"""Weighted incident statuses."""

XDR_ALERT_SOURCES: list[str] = [
    "XDR Agent", "XDR Agent", "XDR Agent",
    "BIOC", "BIOC",
    "Correlation",
    "IOC",
]
"""Weighted alert sources."""

XDR_ALERT_ACTIONS: list[str] = ["detected", "prevented", "blocked"]

XDR_ACTION_TYPES: list[str] = [
    "isolate", "unisolate", "scan", "file_retrieval",
    "script_run", "quarantine", "restore",
]

XDR_ACTION_STATUSES: list[str] = [
    "completed", "completed", "completed", "completed",
    "pending", "in_progress", "failed", "canceled",
]
"""Weighted action statuses."""

XDR_AGENT_VERSIONS: list[str] = [
    "8.3.0.12345",
    "8.2.1.11234",
    "8.1.0.10123",
    "7.9.1.9876",
    "7.8.0.8765",
]

XDR_CONTENT_VERSIONS: list[str] = [
    "890-12345",
    "885-11234",
    "880-10567",
    "875-10012",
]

XDR_ENDPOINT_STATUSES: list[str] = [
    "connected", "connected", "connected", "connected",
    "disconnected",
    "lost",
]

XDR_AUDIT_SUB_TYPES: list[str] = [
    "Login", "Logout", "Policy Change", "Incident Update",
    "Alert Update", "Endpoint Isolation", "Endpoint Unisolation",
    "Script Execution", "IOC Created", "IOC Deleted",
    "Distribution Created", "User Role Change",
]

# ── MITRE ATT&CK mappings ────────────────────────────────────────────────────

XDR_MITRE_TACTICS: list[str] = [
    "TA0001 - Initial Access",
    "TA0002 - Execution",
    "TA0003 - Persistence",
    "TA0004 - Privilege Escalation",
    "TA0005 - Defense Evasion",
    "TA0006 - Credential Access",
    "TA0007 - Discovery",
    "TA0008 - Lateral Movement",
    "TA0009 - Collection",
    "TA0010 - Exfiltration",
    "TA0011 - Command and Control",
    "TA0040 - Impact",
]

XDR_MITRE_TECHNIQUES: list[str] = [
    "T1059.001 - PowerShell",
    "T1055 - Process Injection",
    "T1003 - OS Credential Dumping",
    "T1021.001 - Remote Desktop Protocol",
    "T1566.001 - Spearphishing Attachment",
    "T1078 - Valid Accounts",
    "T1027 - Obfuscated Files or Information",
    "T1083 - File and Directory Discovery",
    "T1105 - Ingress Tool Transfer",
    "T1204.002 - Malicious File",
    "T1547.001 - Registry Run Keys",
    "T1036 - Masquerading",
    "T1071.001 - Web Protocols",
    "T1486 - Data Encrypted for Impact",
]

XDR_ALERT_NAMES: list[str] = [
    "Suspicious PowerShell execution",
    "Malicious file detected by Cortex XDR",
    "Credential theft attempt via LSASS",
    "Ransomware behavior detected",
    "Suspicious process injection",
    "Encoded command line execution",
    "Lateral movement via RDP",
    "Suspicious DLL side-loading",
    "Fileless attack detected",
    "Malicious scheduled task creation",
    "C2 communication detected",
    "Suspicious file modification in system directory",
    "Brute-force login attempt",
    "Living-off-the-land binary execution",
    "Exploit attempt detected",
]

XDR_ALERT_CATEGORIES: list[str] = [
    "Malware", "Exploit", "Credential Access", "Ransomware",
    "Lateral Movement", "Command and Control", "Persistence",
    "Defense Evasion", "Discovery", "Exfiltration",
]

XDR_INCIDENT_DESCRIPTIONS: list[str] = [
    "Ransomware activity detected across multiple endpoints",
    "Credential dumping attempt on domain controller",
    "Suspicious lateral movement between workstations",
    "Malware outbreak detected in engineering department",
    "Phishing campaign targeting executive team",
    "Unauthorized remote access tool detected",
    "Data exfiltration attempt via encrypted channel",
    "Supply chain attack - compromised software update",
    "Brute force attack against VPN gateway",
    "Insider threat - unauthorized data access",
    "Cryptomining malware detected on server farm",
    "Web shell installed on public-facing server",
    "Zero-day exploit attempt on mail server",
    "APT-style intrusion with multiple TTPs",
    "Compromised service account used for privilege escalation",
    "Suspicious DNS tunneling detected",
    "Fileless attack chain using LOLBins",
    "Unauthorized software installation across endpoints",
    "Suspicious Azure AD token manipulation",
    "Multiple failed login attempts followed by success",
]


# ── Pure helper functions ────────────────────────────────────────────────────

def rand_epoch_ms(max_days: int = 90) -> int:
    """Return a random past epoch ms timestamp within the last *max_days* days.

    Args:
        max_days: Upper bound on how far in the past the timestamp may be.

    Returns:
        Integer epoch milliseconds.
    """
    now_ms = int(time.time() * 1000)
    abs_range = abs(max_days) * 24 * 3600 * 1000
    offset_ms = random.randint(0, abs_range)
    if max_days < 0:
        return now_ms + offset_ms  # future timestamp
    return now_ms - offset_ms


def xdr_id(prefix: str = "XDR") -> str:
    """Generate a deterministic XDR-style ID using the seeded RNG.

    Args:
        prefix: String prefix for the ID.

    Returns:
        An ID string like ``"XDR_a3f1b2c4d5e67890"``.
    """
    hex_part = "".join(f"{random.randint(0, 15):x}" for _ in range(16))
    return f"{prefix}_{hex_part}"
