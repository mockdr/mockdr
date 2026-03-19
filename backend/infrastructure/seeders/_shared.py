"""Shared constants and pure helper functions used across domain seeders.

No repository imports — this module must remain free of side effects so
seeders can import it without pulling in the full persistence layer.
"""
import random
import string
from datetime import UTC, datetime, timedelta

from domain.policy import Policy
from utils.id_gen import new_id

# ── Threat / malware reference data ──────────────────────────────────────────

MALWARE_NAMES: list[str] = [
    "Ransom.WannaCry", "Trojan.Emotet", "Backdoor.TrickBot", "Ransom.Ryuk",
    "Trojan.AgentTesla", "Ransom.LockBit", "Exploit.BlueKeep", "Worm.Conficker",
    "Trojan.Dridex", "PUA.Adware.InstallCore", "Ransom.Conti", "Backdoor.Cobalt",
    "Exploit.PrintNightmare", "Trojan.IcedID", "Ransom.BlackCat", "Trojan.Qakbot",
    "Exploit.Log4Shell", "Backdoor.Metasploit", "PUA.Bundleware", "Trojan.RedLine",
    "Ransom.Hive", "Ransom.Vice", "Trojan.GuLoader", "Trojan.NanoCore",
]

MALWARE_FILES: list[str] = [
    "svchost32.exe", "winupdate.exe", "chrome_update.exe", "javaw.exe",
    "setup_installer.exe", "svchosts.exe", "explorer32.exe", "lsass_helper.exe",
    "msiexec32.exe", "rundll32_patch.dll", "inject.dll", "payload.exe",
    "dropper.exe", "loader.exe", "cryptor.exe", "stealer.exe",
]

# ── Agent / OS reference data ─────────────────────────────────────────────────

OS_VARIANTS: list[tuple[str, str, str, str]] = [
    # Current / supported (high weight — repeated for weighted selection)
    ("Windows 10 Pro", "windows", "19045", "23.4.2.3"),
    ("Windows 10 Pro", "windows", "19045", "23.4.2.3"),
    ("Windows 11 Pro", "windows", "22631", "23.4.2.3"),
    ("Windows 11 Pro", "windows", "22631", "23.4.2.3"),
    ("Windows 11 Pro", "windows", "22631", "23.4.2.3"),
    ("Windows Server 2022", "windows", "20348", "23.4.2.3"),
    ("Windows Server 2022", "windows", "20348", "23.4.2.3"),
    ("Windows Server 2019", "windows", "17763", "23.4.2.3"),
    ("macOS Ventura", "macos", "13.6.4", "23.4.2.1"),
    ("macOS Sonoma", "macos", "14.3.1", "23.4.2.1"),
    ("macOS Sonoma", "macos", "14.3.1", "23.4.2.1"),
    ("Ubuntu 22.04 LTS", "linux", "22.04", "23.4.2.2"),
    ("Ubuntu 22.04 LTS", "linux", "22.04", "23.4.2.2"),
    ("Red Hat Enterprise Linux 9", "linux", "9.3", "23.4.2.2"),
    # EOL / unsupported — compliance violations visible across all vendors
    # (~15% of fleet, realistic for SMB with deferred upgrades)
    ("Windows 8.1 Enterprise", "windows", "9600", "23.2.1.1"),
    ("Windows 10 Enterprise 1809", "windows", "17763", "23.2.1.1"),
    ("macOS Big Sur", "macos", "11.7.10", "23.2.1.1"),
    ("CentOS 7", "linux", "7.9", "23.2.1.1"),
]

MACHINE_MODELS: list[str] = [
    "Dell OptiPlex 7090", "HP EliteBook 840 G8", "Lenovo ThinkPad T14",
    "Apple MacBook Pro M3", "Dell PowerEdge R750", "HP ProLiant DL380",
    "Microsoft Surface Pro 9", "Apple Mac mini M2", "Custom Build",
    "VMware, Inc. - VMware7,1", "VMware, Inc. - VMware6,7",
]

CPU_MODELS: list[str] = [
    "Intel(R) Core(TM) i7-1265U CPU @ 1.80GHz",
    "Intel(R) Core(TM) i5-10310U CPU @ 1.70GHz",
    "Intel(R) Xeon(R) Platinum 8358 CPU @ 2.60GHz",
    "Intel(R) Xeon(R) Gold 6230 CPU @ 2.10GHz",
    "Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz",
    "AMD Ryzen 9 5900X 12-Core Processor",
    "AMD EPYC 7742 64-Core Processor",
    "Apple M3 Pro",
]

# ── Active Directory reference data ──────────────────────────────────────────

_AD_DOMAIN = "DC=acmecorp,DC=internal"

AD_OUS: list[str] = [
    f"OU=Workstations,OU=Global,{_AD_DOMAIN}",
    f"OU=Servers,OU=Global,{_AD_DOMAIN}",
    f"OU=Laptops,OU=Global,{_AD_DOMAIN}",
    f"OU=VDI,OU=Xen,OU=Global,{_AD_DOMAIN}",
    f"OU=Kiosk,OU=Global,{_AD_DOMAIN}",
]

AD_GROUPS_POOL: list[str] = [
    f"CN=Domain Computers,CN=Users,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-Windows-10-22H2-Upgrade,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-Windows-11-23H2-Upgrade,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-EDR-Agent-Forced,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-SMBv1-Disable,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-NTLMv1-Disable,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-Windows-Firewall-Enable,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-Edge-Chromium-Latest,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-7-Zip-24.09,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-NotepadPlusPlus-8.6,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-PKI-Computer-Default,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-IE11-Disable,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-NetBios-LLMNR-Disable,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-Putty-0.81-Machine,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-WKS-SCCM-DLP-USB-Restrictions,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=APP-MDM-Intune-Enrollment,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-Collaboration-Suite-Users,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-Endpoint-Mgmt-Clients,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-SecureVPN-CorpVPN-Clients,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=RES-OPS-Workstation-Administrators,OU=Workstations,OU=Groups,OU=Global,{_AD_DOMAIN}",
]

USER_AD_GROUPS_POOL: list[str] = [
    f"CN=Domain Users,CN=Users,{_AD_DOMAIN}",
    f"CN=APP-Collaboration-Suite-Users,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-BI-Pro-License,OU=Distribution Lists,OU=Messaging,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-HR-Portal-Employee,OU=APP,OU=SG,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=APP-HR-Portal-Manager,OU=APP,OU=SG,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=APP-ERP-Finance-ReadOnly,OU=APP,OU=SG,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=APP-ERP-Procurement-Users,OU=APP,OU=SG,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=APP-SecureVPN-CorpVPN-Users,OU=Computed,OU=Groups,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-Legacy-Access-Allowed,OU=Computed,OU=Groups,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-MFA-Enforced,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-Endpoint-Mgmt-License,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=APP-DLP-Exclusion-Approved,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-USR-SCCM-Visio-Professional-2021,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-USR-SCCM-ERP-GUI-Client-8.1,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=DIST-APP-POL-USR-SCCM-ServiceDesk-Standard-Users,OU=Policy,OU=Deployment,OU=Groups,OU=Global,{_AD_DOMAIN}",
    f"CN=SEC-IAM-All-Employees,OU=Computed,OU=Groups,OU=Common,{_AD_DOMAIN}",
    f"CN=SEC-IAM-EMEA-Users,OU=Computed,OU=Groups,OU=Common,{_AD_DOMAIN}",
    f"CN=All-Mobile-Device-Users,OU=Groups,OU=Provisioned,OU=Common,{_AD_DOMAIN}",
]

# ── Alert / threat classification enums ──────────────────────────────────────

MITIGATION_STATUSES: list[str] = [
    "mitigated", "mitigated", "mitigated", "mitigated",
    "not_mitigated", "not_mitigated", "marked_as_benign",
]
CLASSIFICATIONS: list[str] = [
    "Malware", "Malware", "Malware", "Malware",
    "Ransomware", "PUA", "Exploit", "Trojan",
]
INCIDENT_STATUSES: list[str] = [
    "unresolved", "unresolved", "unresolved",
    "in_progress", "in_progress", "resolved",
]
ANALYST_VERDICTS: list[str] = [
    "undefined", "undefined", "undefined",
    "true_positive", "false_positive", "suspicious",
]
CONFIDENCE_LEVELS: list[str] = [
    "malicious", "malicious", "malicious", "suspicious", "n/a",
]

# Alert-specific enums — UPPERCASE per real SentinelOne API contract
ALERT_SEVERITIES: list[str] = [
    "Critical", "High", "High", "Medium", "Medium", "Low", "Info",
]
ALERT_VERDICTS: list[str] = [
    "Undefined", "Undefined", "True positive", "False positive", "Suspicious",
]
ALERT_INCIDENT_STATUSES: list[str] = [
    "Unresolved", "Unresolved", "In progress", "Resolved", "Unresolved",
]

# ── MITRE ATT&CK reference data ───────────────────────────────────────────────

MITRE_TACTICS: list[str] = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact",
]
MITRE_TECHNIQUES: list[str] = [
    "T1059.001", "T1055", "T1003", "T1021.001", "T1566.001",
    "T1078", "T1027", "T1083", "T1105", "T1204.002",
]

# ── Activity log catalogue ────────────────────────────────────────────────────

ACTIVITY_CATALOG: list[tuple[int, str]] = [
    (19, "Agent registered"),
    (20, "Agent unregistered"),
    (25, "Threat detected"),
    (26, "Threat mitigated"),
    (27, "Threat resolved"),
    (52, "Agent disconnected from network"),
    (53, "Agent reconnected to network"),
    (54, "Full disk scan started"),
    (55, "Full disk scan completed"),
    (90, "User logged in"),
    (120, "Policy updated"),
    (128, "Exclusion added"),
    (2001, "Deep Visibility query initiated"),
    (3016, "Threat marked as benign"),
    (3784, "Threat marked as malicious"),
    (4003, "Hash added to blocklist"),
    (5009, "Agent upgraded"),
    (5126, "Site created"),
    (5232, "Group created"),
]

# ── Installed applications catalogue ─────────────────────────────────────────

APP_CATALOG: list[tuple[str, str, str]] = [
    # ── Standard corporate software ──────────────────────────────────────────
    ("Microsoft Office", "16.0.17328.20096", "Microsoft Corporation"),
    ("Google Chrome", "123.0.6312.86", "Google LLC"),
    ("Mozilla Firefox", "124.0.1", "Mozilla"),
    ("Adobe Acrobat Reader", "23.8.20555", "Adobe Inc."),
    ("Zoom", "5.17.11", "Zoom Video Communications"),
    ("Slack", "4.36.140", "Slack Technologies"),
    ("7-Zip", "23.01", "Igor Pavlov"),
    ("Python 3.12", "3.12.2", "Python Software Foundation"),
    ("Git", "2.44.0", "The Git Development Community"),
    ("Visual Studio Code", "1.88.0", "Microsoft Corporation"),
    ("OpenVPN", "2.6.9", "OpenVPN Technologies"),
    ("Notepad++", "8.6.4", "Don Ho"),
    ("VLC media player", "3.0.20", "VideoLAN"),
    ("TeamViewer", "15.52.4", "TeamViewer Germany GmbH"),
    # ── EDR / security agents (installed on most endpoints) ──────────────────
    ("SentinelOne Agent", "23.4.2.3", "SentinelOne Inc."),
    ("CrowdStrike Falcon Sensor", "7.10.17706.0", "CrowdStrike Inc."),
    ("Microsoft Defender for Endpoint", "10.8760.19041.2545", "Microsoft Corporation"),
    ("Cortex XDR Agent", "8.3.0.12345", "Palo Alto Networks"),
    ("Elastic Endpoint Security", "8.13.0", "Elastic N.V."),
    # ── EOL / end-of-life software (compliance risk) ─────────────────────────
    ("Adobe Flash Player", "32.0.0.465", "Adobe Inc."),
    ("Java Runtime Environment", "1.8.0_202", "Oracle Corporation"),
    ("Microsoft Silverlight", "5.1.50918.0", "Microsoft Corporation"),
    ("Windows 7 Embedded", "6.1.7601", "Microsoft Corporation"),
    ("Internet Explorer", "11.0.22621.1", "Microsoft Corporation"),
    ("Python 2.7", "2.7.18", "Python Software Foundation"),
    ("Apache Log4j", "2.14.1", "Apache Software Foundation"),
    # ── Torrent / P2P clients (policy violation) ─────────────────────────────
    ("qBittorrent", "4.6.3", "qBittorrent Project"),
    ("uTorrent", "3.6.0.46922", "BitTorrent Inc."),
    ("BitTorrent", "7.11.0.47117", "BitTorrent Inc."),
    # ── Potentially malicious / dual-use tools ───────────────────────────────
    ("Mimikatz", "2.2.0", "Benjamin Delpy"),
    ("Nmap", "7.94", "Nmap Project"),
    ("Wireshark", "4.2.3", "Wireshark Foundation"),
    ("PsExec", "2.43", "Microsoft Sysinternals"),
    ("Cobalt Strike", "4.9", "Fortra LLC"),
]

# ── EDR agent version pools (current + outdated for compliance testing) ───────

EDR_VERSION_POOL: dict[str, list[tuple[str, bool]]] = {
    "SentinelOne Agent": [
        ("23.4.2.3", True),   # current
        ("23.3.1.8", True),   # current - 1
        ("23.2.3.6", False),  # outdated
        ("22.3.5.4", False),  # EOL
        ("21.7.6.2", False),  # EOL
    ],
    "CrowdStrike Falcon Sensor": [
        ("7.10.17706.0", True),
        ("7.08.17506.0", True),
        ("6.58.16704.0", False),  # outdated
        ("6.44.15806.0", False),  # EOL
        ("6.33.15005.0", False),  # EOL
    ],
    "Microsoft Defender for Endpoint": [
        ("10.8760.19041.2545", True),
        ("10.8560.18363.2345", True),
        ("10.8210.17763.1845", False),  # outdated
        ("10.7562.17134.1245", False),  # EOL
    ],
    "Cortex XDR Agent": [
        ("8.3.0.12345", True),
        ("8.2.1.11234", True),
        ("7.9.1.9876", False),  # outdated
        ("7.5.0.8765", False),  # EOL
    ],
    "Elastic Endpoint Security": [
        ("8.13.0", True),
        ("8.12.2", True),
        ("8.8.0", False),   # outdated
        ("7.17.18", False),  # EOL
    ],
}
"""Version pools per EDR product.  ``True`` = current/supported, ``False`` = outdated/EOL."""

# ── Deep Visibility event types ───────────────────────────────────────────────

DV_EVENT_TYPES: list[str] = [
    "Process", "File", "Network", "Registry", "DNS", "Scheduled Task", "Module Load",
]

# ── Pure helper functions ─────────────────────────────────────────────────────


def ago(days: int = 0, hours: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp *days* and *hours* in the past.

    Args:
        days: Number of days to subtract from now.
        hours: Number of hours to subtract from now.

    Returns:
        Formatted timestamp string ``YYYY-MM-DDTHH:MM:SS.000Z``.
    """
    dt = datetime.now(UTC) - timedelta(days=days, hours=hours)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rand_ago(max_days: int = 90) -> str:
    """Return an ISO-8601 UTC timestamp at a random point within the last *max_days* days.

    Args:
        max_days: Upper bound on how far in the past the timestamp may be.

    Returns:
        Formatted timestamp string ``YYYY-MM-DDTHH:MM:SS.000Z``.
    """
    return ago(days=random.randint(0, max_days), hours=random.randint(0, 23))


def passphrase() -> str:
    """Return a random four-word passphrase in ``XXXX-XXXX-XXXX-XXXX`` format.

    Returns:
        Uppercase hyphen-separated passphrase string.
    """
    return "-".join(
        "".join(random.choices(string.ascii_uppercase, k=4))
        for _ in range(4)
    )


def make_policy(scope_id: str, scope_type: str) -> Policy:
    """Construct a default ``Policy`` domain object for a site or group.

    Args:
        scope_id: ID of the site or group this policy is attached to.
        scope_type: Either ``"site"`` or ``"group"``.

    Returns:
        A fully-populated :class:`~domain.policy.Policy` instance.
    """
    return Policy(
        id=new_id(),
        scopeId=scope_id,
        scopeType=scope_type,
        mitigationMode=random.choice(["protect", "protect", "detect"]),
        mitigationModeSuspicious="detect",
        monitorOnWrite=True,
        monitorOnExecute=True,
        blockOnWrite=True,
        blockOnExecute=True,
        scanNewAgents=True,
        scanOnWritten=True,
        autoMitigate=True,
        updatedAt=rand_ago(30),
        engines={
            "reputation": True, "staticAi": True, "behavioralAi": True,
            "cloud": True, "filelessAttack": True, "networkAttack": True,
        },
        agentUi={
            "agentUiOn": True, "showAgentReports": True,
            "showSuspicious": True, "maxFreeSpaceForLog": 2048,
        },
        firewall={"ipcFirewall": True},
    )
