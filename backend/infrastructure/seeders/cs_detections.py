"""CrowdStrike detections seeder — creates detection records linked to hosts."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_detection import CsDetection
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import (
    CS_BEHAVIOR_CMDLINES,
    CS_BEHAVIOR_FILENAMES,
    CS_CID,
    CS_DETECTION_SCENARIOS,
    CS_DETECTION_TACTICS,
    CS_DETECTION_TECHNIQUES,
    cs_hex_id,
    severity_display,
)
from repository.cs_detection_repo import cs_detection_repo
from repository.cs_host_repo import cs_host_repo

_COUNT: int = 30

_STATUS_WEIGHTS: list[str] = (
    ["new"] * 8
    + ["in_progress"] * 5
    + ["true_positive"] * 3
    + ["false_positive"] * 2
    + ["closed"] * 2
)


def _build_behavior(fake: Faker, host_id: str, timestamp: str) -> dict:
    """Build a single behavior dict for a detection.

    Args:
        fake: Shared Faker instance.
        host_id: The device_id this behavior occurred on.
        timestamp: ISO-8601 timestamp for the behavior.

    Returns:
        Dict matching CrowdStrike behavior schema.
    """
    tactic = random.choice(CS_DETECTION_TACTICS)
    technique = random.choice(CS_DETECTION_TECHNIQUES)
    filename = random.choice(CS_BEHAVIOR_FILENAMES)
    scenario = random.choice(CS_DETECTION_SCENARIOS)
    severity = random.randint(10, 100)

    return {
        "behavior_id": cs_hex_id(),
        "device_id": host_id,
        "timestamp": timestamp,
        "template_instance_id": str(random.randint(1, 50)),
        "filename": filename,
        "filepath": f"\\Device\\HarddiskVolume3\\Windows\\System32\\{filename}",
        "cmdline": random.choice(CS_BEHAVIOR_CMDLINES),
        "scenario": scenario,
        "severity": severity,
        "confidence": random.randint(50, 100),
        "ioc_type": "",
        "ioc_value": "",
        "ioc_source": "",
        "tactic": tactic,
        "tactic_id": f"TA{random.randint(1, 14):04d}",
        "technique": technique.split(".")[0],
        "technique_id": technique,
        "display_name": f"{scenario}: {filename}",
        "objective": f"Falcon Detection Method - {scenario}",
        "sha256": fake.sha256(),
        "md5": fake.md5(),
        "parent_details": {
            "parent_sha256": fake.sha256(),
            "parent_md5": fake.md5(),
            "parent_cmdline": "C:\\Windows\\explorer.exe",
            "parent_process_graph_id": f"pid:{CS_CID}:{random.randint(10**8, 10**9)}",
        },
        "pattern_disposition": random.randint(0, 2176),
        "pattern_disposition_details": {
            "indicator": False,
            "detect": True,
            "inddet_mask": False,
            "sensor_only": False,
            "rooting": False,
            "kill_process": random.choice([True, False]),
            "kill_subprocess": random.choice([True, False]),
            "quarantine_machine": False,
            "quarantine_file": random.choice([True, False]),
            "policy_disabled": False,
            "kill_parent": False,
            "operation_blocked": random.choice([True, False]),
            "process_blocked": random.choice([True, False]),
        },
        "user_name": fake.user_name(),
        "user_id": f"S-1-5-21-{random.randint(10**9, 4*10**9-1)}-{random.randint(10**3, 10**4)}",
        "control_graph_id": f"ctg:{CS_CID}:{random.randint(10**8, 10**9)}",
        "triggering_process_graph_id": f"pid:{CS_CID}:{random.randint(10**8, 10**9)}",
        "alleged_filetype": "exe",
    }


def seed_cs_detections(fake: Faker, host_ids: list[str]) -> list[str]:
    """Create CrowdStrike detection records linked to seeded hosts.

    Generates ``_COUNT`` detections, each tied to a random host with 1-3
    behaviors containing realistic filenames, MITRE tactics, and scenarios.

    Args:
        fake: Shared Faker instance (seeded externally).
        host_ids: List of CS ``device_id`` strings from host seeder.

    Returns:
        List of ``composite_id`` strings.
    """
    all_hosts = cs_host_repo.list_all()
    host_lookup = {h.device_id: h for h in all_hosts}
    detection_ids: list[str] = []

    for i in range(1, _COUNT + 1):
        composite_id = f"ldt:{CS_CID}:{i}"
        detection_ids.append(composite_id)

        host_id = random.choice(host_ids)
        host = host_lookup.get(host_id)

        created_ts = rand_ago(30)
        first_behavior_ts = created_ts
        last_behavior_ts = created_ts

        # Generate 1-3 behaviors
        behavior_count = random.randint(1, 3)
        behaviors: list[dict] = []
        for _ in range(behavior_count):
            b_ts = rand_ago(30)
            behaviors.append(_build_behavior(fake, host_id, b_ts))
            if b_ts < first_behavior_ts:
                first_behavior_ts = b_ts
            if b_ts > last_behavior_ts:
                last_behavior_ts = b_ts

        max_severity = random.randint(10, 100)
        status = random.choice(_STATUS_WEIGHTS)

        # Build device snapshot dict from host
        device_dict: dict = {}
        if host is not None:
            device_dict = {
                "device_id": host.device_id,
                "cid": host.cid,
                "hostname": host.hostname,
                "local_ip": host.local_ip,
                "external_ip": host.external_ip,
                "mac_address": host.mac_address,
                "platform_name": host.platform_name,
                "platform_id": host.platform_id,
                "os_version": host.os_version,
                "agent_version": host.agent_version,
                "product_type_desc": host.product_type_desc,
                "machine_domain": host.machine_domain,
                "site_name": host.site_name,
                "status": host.status,
                "first_seen": host.first_seen,
                "last_seen": host.last_seen,
            }

        seconds_to_triaged = random.randint(60, 86400) if status != "new" else 0
        seconds_to_resolved = (
            random.randint(3600, 259200)
            if status in ("closed", "true_positive", "false_positive")
            else 0
        )

        cs_detection_repo.save(CsDetection(
            composite_id=composite_id,
            device=device_dict,
            behaviors=behaviors,
            max_severity=max_severity,
            max_severity_displayname=severity_display(max_severity),
            max_confidence=random.randint(50, 100),
            status=status,
            show_in_ui=True,
            created_timestamp=created_ts,
            first_behavior=first_behavior_ts,
            last_behavior=last_behavior_ts,
            date_updated=rand_ago(5),
            assigned_to_name="" if status == "new" else fake.name(),
            assigned_to_uid="" if status == "new" else fake.email(),
            seconds_to_triaged=seconds_to_triaged,
            seconds_to_resolved=seconds_to_resolved,
            hostinfo={"domain": host.machine_domain if host else ""},
            email_sent=status != "new",
        ))

    return detection_ids
