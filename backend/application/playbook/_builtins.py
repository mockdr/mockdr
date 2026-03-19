"""Pre-built incident simulation playbooks."""

from domain.activity import ActivityType as AT  # noqa: N817

BUILTIN_PLAYBOOKS = [
    {
        "id": "phishing_excel_macro",
        "title": "Phishing via Excel Macro",
        "description": "User receives phishing email, opens malicious macro-enabled spreadsheet. SentinelOne detects and quarantines.",  # noqa: E501
        "category": "malware",
        "severity": "HIGH",
        "estimatedDurationMs": 30000,
        "steps": [
            {
                "stepId": "agent_online",
                "label": "Agent comes online",
                "delayMs": 0,
                "action": "activity",
                "activityType": AT.AGENT_CONNECTED,
                "description": "Agent connected to management console",
            },
            {
                "stepId": "user_login",
                "label": "User logs in",
                "delayMs": 2000,
                "action": "activity",
                "activityType": AT.USER_SESSION,
                "description": "Interactive user session started: john.doe@corp.com",
            },
            {
                "stepId": "outlook_start",
                "label": "Outlook opens",
                "delayMs": 5000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Process started: OUTLOOK.EXE (PID 4821)",
            },
            {
                "stepId": "excel_open",
                "label": "Malicious Excel file opened",
                "delayMs": 9000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "File opened via email attachment: Q4-Budget-FINAL.xlsm (macro-enabled workbook)",  # noqa: E501
            },
            {
                "stepId": "macro_exec",
                "label": "Macro execution detected",
                "delayMs": 11000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Suspicious macro execution: EXCEL.EXE spawned CMD.EXE → PowerShell.exe -enc [base64]",  # noqa: E501
            },
            {
                "stepId": "threat_detected",
                "label": "Threat detected",
                "delayMs": 12000,
                "action": "threat",
                "threatName": "Trojan.MacroExec",
                "fileName": "Q4-Budget-FINAL.xlsm",
                "classification": "Trojan",
                "confidenceLevel": "malicious",
                "mitreTactic": "Initial Access",
                "mitreTechnique": "T1566.001",
                "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            },
            {
                "stepId": "agent_infected",
                "label": "Agent marked infected",
                "delayMs": 12500,
                "action": "agent_state",
                "infected": True,
                "activeThreats": 1,
                "networkStatus": "connected",
            },
            {
                "stepId": "alert_raised",
                "label": "Alert raised",
                "delayMs": 13000,
                "action": "alert",
                "severity": "HIGH",
                "category": "Malware",
                "description": "Macro-enabled document spawned suspicious child process",
                "mitreTactic": "Initial Access",
                "mitreTechnique": "T1566.001",
            },
            {
                "stepId": "quarantine",
                "label": "Policy response (protect → quarantine / detect → alert only)",
                "delayMs": 15000,
                "action": "mitigate",
            },
        ],
    },
    {
        "id": "ransomware_outbreak",
        "title": "Ransomware Outbreak",
        "description": "Ransomware detected encrypting files. Agent isolated from network automatically.",  # noqa: E501
        "category": "ransomware",
        "severity": "CRITICAL",
        "estimatedDurationMs": 25000,
        "steps": [
            {
                "stepId": "suspicious_process",
                "label": "Suspicious process starts",
                "delayMs": 0,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Unusual process tree: svchost.exe (parent: userinit.exe) → vssadmin.exe delete shadows",  # noqa: E501
            },
            {
                "stepId": "vss_delete",
                "label": "Shadow copies deleted",
                "delayMs": 3000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Volume Shadow Copy deletion attempt detected: vssadmin.exe delete shadows /all /quiet",  # noqa: E501
            },
            {
                "stepId": "encryption_starts",
                "label": "File encryption detected",
                "delayMs": 6000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Mass file rename detected: 847 files modified with extension .locked in C:\\Users\\",  # noqa: E501
            },
            {
                "stepId": "threat_detected",
                "label": "Ransomware detected",
                "delayMs": 7000,
                "action": "threat",
                "threatName": "Ransom.LockBit",
                "fileName": "svchost.exe",
                "classification": "Ransomware",
                "confidenceLevel": "malicious",
                "mitreTactic": "Impact",
                "mitreTechnique": "T1486",
                "sha1": "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",
            },
            {
                "stepId": "agent_infected",
                "label": "Agent state updated",
                "delayMs": 7500,
                "action": "agent_state",
                "infected": True,
                "activeThreats": 3,
                "networkStatus": "disconnected",
            },
            {
                "stepId": "alert_raised",
                "label": "Critical alert raised",
                "delayMs": 8000,
                "action": "alert",
                "severity": "CRITICAL",
                "category": "Ransomware",
                "description": "Active ransomware encrypting user files. Automatic network isolation applied.",  # noqa: E501
                "mitreTactic": "Impact",
                "mitreTechnique": "T1486",
            },
            {
                "stepId": "isolation",
                "label": "Network isolation applied",
                "delayMs": 9000,
                "action": "activity",
                "activityType": AT.NETWORK_ISOLATED,
                "description": "Agent network isolated automatically: ransomware behaviour exceeded threshold",  # noqa: E501
            },
            {
                "stepId": "policy_response",
                "label": "Policy response (protect → rollback-remediation / detect → alert only)",
                "delayMs": 10000,
                "action": "mitigate",
            },
            {
                "stepId": "analyst_notified",
                "label": "SOC notified",
                "delayMs": 12000,
                "action": "activity",
                "activityType": AT.ADMIN_NOTE,
                "description": "Incident escalated to SOC: Ransom.LockBit on {agentName} — P1 response required",  # noqa: E501
            },
        ],
    },
    {
        "id": "lateral_movement",
        "title": "Lateral Movement Detection",
        "description": "Attacker pivots from compromised host using PsExec and stolen credentials.",
        "category": "lateral",
        "severity": "HIGH",
        "estimatedDurationMs": 35000,
        "steps": [
            {
                "stepId": "psexec_detected",
                "label": "PsExec activity detected",
                "delayMs": 0,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Remote execution tool detected: PsExec.exe targeting 192.168.1.0/24",  # noqa: E501
            },
            {
                "stepId": "threat_psexec",
                "label": "PsExec threat created",
                "delayMs": 1000,
                "action": "threat",
                "threatName": "HackTool.PsExec",
                "fileName": "PsExec.exe",
                "classification": "PUA",
                "confidenceLevel": "suspicious",
                "mitreTactic": "Lateral Movement",
                "mitreTechnique": "T1021.002",
                "sha1": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15",
            },
            {
                "stepId": "agent_suspicious",
                "label": "Agent flagged suspicious",
                "delayMs": 1500,
                "action": "agent_state",
                "infected": True,
                "activeThreats": 1,
                "networkStatus": "connected",
            },
            {
                "stepId": "credential_dump",
                "label": "Credential dumping attempt",
                "delayMs": 8000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "LSASS memory access detected: mimikatz pattern — sekurlsa::logonpasswords",  # noqa: E501
            },
            {
                "stepId": "alert_lateral",
                "label": "Lateral movement alert",
                "delayMs": 9000,
                "action": "alert",
                "severity": "HIGH",
                "category": "Lateral Movement",
                "description": "Attacker pivoting via PsExec with harvested credentials",
                "mitreTactic": "Lateral Movement",
                "mitreTechnique": "T1021.002",
            },
            {
                "stepId": "rdp_attempt",
                "label": "RDP connection attempts",
                "delayMs": 15000,
                "action": "activity",
                "activityType": AT.PROCESS_EVENT,
                "description": "Multiple RDP authentication attempts from {agentName}: 47 failed logons in 60s",  # noqa: E501
            },
            {
                "stepId": "blocked",
                "label": "Policy response (protect → kill / detect → alert only)",
                "delayMs": 20000,
                "action": "mitigate",
            },
        ],
    },
    {
        "id": "quiet_day_reset",
        "title": "Quiet Day (Reset)",
        "description": "Resolve all threats, bring all agents online — clean baseline state.",
        "category": "reset",
        "severity": "LOW",
        "estimatedDurationMs": 5000,
        "steps": [
            {
                "stepId": "resolve_threats",
                "label": "Resolve all threats",
                "delayMs": 0,
                "action": "resolve_all_threats",
            },
            {
                "stepId": "heal_agents",
                "label": "Bring all agents online",
                "delayMs": 1000,
                "action": "heal_all_agents",
            },
            {
                "stepId": "activity_clear",
                "label": "Environment cleared",
                "delayMs": 2000,
                "action": "activity",
                "activityType": AT.ADMIN_NOTE,
                "description": "All threats resolved. Environment returned to clean state.",
            },
        ],
    },
]

def get_playbook(playbook_id: str) -> dict | None:
    """Look up a built-in playbook by ID.

    Args:
        playbook_id: The playbook identifier string.

    Returns:
        The matching playbook dict, or ``None`` if not found.
    """
    return next((p for p in BUILTIN_PLAYBOOKS if p["id"] == playbook_id), None)
