"""Elastic Security-specific reference data and helper functions.

Constants and pure helpers shared across all ES domain seeders.
No repository imports -- this module must remain free of side effects.
"""
from __future__ import annotations

import random

# ── Fleet / policy constants ──────────────────────────────────────────────────

ES_POLICY_NAMES: list[str] = [
    "Default Endpoint Policy",
    "Server Protection Policy",
    "Workstation Policy",
]

ES_SEVERITY_LEVELS: list[str] = ["low", "medium", "high", "critical"]

# ── KQL detection queries ─────────────────────────────────────────────────────

ES_KQL_QUERIES: list[str] = [
    'process.name: "powershell.exe" and process.args: "-enc*"',
    'process.name: "cmd.exe" and process.args: "/c whoami"',
    'process.name: "certutil.exe" and process.args: "-urlcache"',
    'process.name: "bitsadmin.exe" and process.args: "/transfer"',
    'process.name: "mshta.exe" and process.args: "vbscript*"',
    'process.name: "regsvr32.exe" and process.args: "/s /n /u"',
    'event.category: "network" and destination.port: 4444',
    'file.extension: "exe" and file.path: "C:\\Users\\*\\AppData\\Local\\Temp\\*"',
    'registry.path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*"',
    'process.name: "wmic.exe" and process.args: "process call create"',
    'dns.question.name: *dnscat* or dns.question.name: *tunnel*',
    'event.category: "authentication" and event.outcome: "failure"',
    'process.name: "rundll32.exe" and process.args: "javascript*"',
    'file.hash.sha256: * and event.action: "creation"',
    'process.parent.name: "winword.exe" and process.name: "cmd.exe"',
]

# ── EQL detection queries ─────────────────────────────────────────────────────

ES_EQL_QUERIES: list[str] = [
    'process where process.name == "rundll32.exe"',
    'process where process.name == "powershell.exe" and process.args : "-enc*"',
    'file where file.extension == "exe" and file.path : "C:\\\\Users\\\\*\\\\Downloads\\\\*"',
    'sequence by host.id [process where process.name == "cmd.exe"] [network where destination.port == 443]',
    'process where process.parent.name == "explorer.exe" and process.name : ("cmd.exe", "powershell.exe")',
    'registry where registry.path : "*\\\\CurrentVersion\\\\Run\\\\*"',
    'network where destination.port in (4444, 5555, 8080) and source.port > 49152',
    'process where process.name == "wscript.exe" and process.args : "*.vbs"',
]

# ── MITRE ATT&CK mappings ────────────────────────────────────────────────────

ES_MITRE_TACTICS: list[dict] = [
    {"id": "TA0001", "name": "Initial Access", "reference": "https://attack.mitre.org/tactics/TA0001/"},
    {"id": "TA0002", "name": "Execution", "reference": "https://attack.mitre.org/tactics/TA0002/"},
    {"id": "TA0003", "name": "Persistence", "reference": "https://attack.mitre.org/tactics/TA0003/"},
    {"id": "TA0004", "name": "Privilege Escalation", "reference": "https://attack.mitre.org/tactics/TA0004/"},
    {"id": "TA0005", "name": "Defense Evasion", "reference": "https://attack.mitre.org/tactics/TA0005/"},
    {"id": "TA0006", "name": "Credential Access", "reference": "https://attack.mitre.org/tactics/TA0006/"},
    {"id": "TA0007", "name": "Discovery", "reference": "https://attack.mitre.org/tactics/TA0007/"},
    {"id": "TA0008", "name": "Lateral Movement", "reference": "https://attack.mitre.org/tactics/TA0008/"},
    {"id": "TA0009", "name": "Collection", "reference": "https://attack.mitre.org/tactics/TA0009/"},
    {"id": "TA0011", "name": "Command and Control", "reference": "https://attack.mitre.org/tactics/TA0011/"},
    {"id": "TA0040", "name": "Impact", "reference": "https://attack.mitre.org/tactics/TA0040/"},
    {"id": "TA0010", "name": "Exfiltration", "reference": "https://attack.mitre.org/tactics/TA0010/"},
]

ES_MITRE_TECHNIQUES: list[dict] = [
    {"id": "T1059.001", "name": "PowerShell", "reference": "https://attack.mitre.org/techniques/T1059/001/"},
    {"id": "T1055", "name": "Process Injection", "reference": "https://attack.mitre.org/techniques/T1055/"},
    {"id": "T1003.001", "name": "LSASS Memory", "reference": "https://attack.mitre.org/techniques/T1003/001/"},
    {"id": "T1547.001", "name": "Registry Run Keys", "reference": "https://attack.mitre.org/techniques/T1547/001/"},
    {"id": "T1071.001", "name": "Web Protocols", "reference": "https://attack.mitre.org/techniques/T1071/001/"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "reference": "https://attack.mitre.org/techniques/T1486/"},
    {"id": "T1566.001", "name": "Spearphishing Attachment", "reference": "https://attack.mitre.org/techniques/T1566/001/"},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "reference": "https://attack.mitre.org/techniques/T1021/001/"},
    {"id": "T1218.011", "name": "Rundll32", "reference": "https://attack.mitre.org/techniques/T1218/011/"},
    {"id": "T1204.002", "name": "Malicious File", "reference": "https://attack.mitre.org/techniques/T1204/002/"},
    {"id": "T1027", "name": "Obfuscated Files or Information", "reference": "https://attack.mitre.org/techniques/T1027/"},
    {"id": "T1105", "name": "Ingress Tool Transfer", "reference": "https://attack.mitre.org/techniques/T1105/"},
]

# ── Detection rule names ──────────────────────────────────────────────────────

ES_RULE_NAMES: list[str] = [
    "Encoded PowerShell Execution",
    "Suspicious Certutil Network Activity",
    "LSASS Memory Credential Dumping",
    "Rundll32 with Unusual Arguments",
    "Registry Run Key Persistence",
    "Suspicious WMIC Process Creation",
    "DNS Tunneling Activity",
    "Unusual Child Process of Office Application",
    "BITSAdmin File Download",
    "MSHTA VBScript Execution",
    "Regsvr32 Scriptlet Execution",
    "Outbound Connection on Non-Standard Port",
    "Executable Written to Temp Directory",
    "Suspicious Authentication Failures",
    "Command Shell Spawned via Explorer",
    "WScript VBS Execution",
    "Process Injection via Rundll32",
    "Lateral Movement via RDP",
    "Ransomware File Encryption Behavior",
    "Credential Theft via Mimikatz",
    "Suspicious Network Beacon Pattern",
    "Malware Written to Downloads Folder",
    "Scheduled Task Persistence",
    "Data Exfiltration via DNS Query",
    "Supply Chain Compromise Indicator",
]

# ── Process names for alert generation ────────────────────────────────────────

ES_PROCESS_NAMES: list[str] = [
    "powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
    "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe",
    "bitsadmin.exe", "wmic.exe", "svchost.exe", "conhost.exe",
    "bash", "python3", "curl", "wget",
]

# ── Case tags ─────────────────────────────────────────────────────────────────

ES_CASE_TAGS: list[str] = [
    "ransomware", "phishing", "apt", "incident-response",
    "threat-hunting", "malware",
]

# ── UUID generator ────────────────────────────────────────────────────────────

def es_uuid() -> str:
    """Generate a deterministic UUID-like string using the seeded RNG.

    Returns:
        A UUID v4-format string generated deterministically.
    """
    # Use random to keep it deterministic with the global seed
    hex_str = "".join(f"{random.randint(0, 255):02x}" for _ in range(16))
    return (
        f"{hex_str[:8]}-{hex_str[8:12]}-4{hex_str[13:16]}"
        f"-{random.choice('89ab')}{hex_str[17:20]}-{hex_str[20:32]}"
    )
