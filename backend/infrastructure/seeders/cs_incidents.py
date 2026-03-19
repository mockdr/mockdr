"""CrowdStrike incidents seeder — creates incident records grouping hosts."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_incident import CsIncident
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import (
    CS_CID,
    CS_DETECTION_TACTICS,
    CS_DETECTION_TECHNIQUES,
    CS_INCIDENT_NAMES,
    severity_display,
)
from repository.cs_host_repo import cs_host_repo
from repository.cs_incident_repo import cs_incident_repo

_COUNT: int = 15

# status: 20=New, 25=Reopened, 30=InProgress, 40=Closed
_STATUS_WEIGHTS: list[int] = (
    [20] * 6
    + [30] * 8
    + [40] * 4
    + [25] * 2
)

_STATE_MAP: dict[int, str] = {
    20: "open",
    25: "open",
    30: "open",
    40: "closed",
}


def seed_cs_incidents(
    fake: Faker,
    host_ids: list[str],
    detection_ids: list[str],
) -> list[str]:
    """Create CrowdStrike incident records grouping hosts and detections.

    Generates ``_COUNT`` incidents, each referencing 1-5 random hosts and
    populated with MITRE tactics/techniques from the shared catalog.

    Args:
        fake: Shared Faker instance (seeded externally).
        host_ids: List of CS ``device_id`` strings.
        detection_ids: List of detection ``composite_id`` strings.

    Returns:
        List of ``incident_id`` strings.
    """
    all_hosts = cs_host_repo.list_all()
    host_lookup = {h.device_id: h for h in all_hosts}
    incident_ids: list[str] = []

    for i in range(1, _COUNT + 1):
        incident_id = f"inc:{CS_CID}:{i}"
        incident_ids.append(incident_id)

        # Pick 1-5 random hosts for this incident
        host_count = random.randint(1, min(5, len(host_ids)))
        chosen_host_ids = random.sample(host_ids, host_count)

        # Build host snapshot dicts
        hosts_data: list[dict] = []
        for hid in chosen_host_ids:
            host = host_lookup.get(hid)
            if host is not None:
                hosts_data.append({
                    "device_id": host.device_id,
                    "cid": host.cid,
                    "hostname": host.hostname,
                    "platform_name": host.platform_name,
                    "os_version": host.os_version,
                    "external_ip": host.external_ip,
                    "local_ip": host.local_ip,
                    "site_name": host.site_name,
                    "machine_domain": host.machine_domain,
                })

        status = random.choice(_STATUS_WEIGHTS)
        state = _STATE_MAP.get(status, "open")
        fine_score = random.randint(10, 100)

        tactic_count = random.randint(1, 3)
        technique_count = random.randint(1, 3)
        tactics = random.sample(
            CS_DETECTION_TACTICS,
            min(tactic_count, len(CS_DETECTION_TACTICS)),
        )
        techniques = random.sample(
            CS_DETECTION_TECHNIQUES,
            min(technique_count, len(CS_DETECTION_TECHNIQUES)),
        )

        created_ts = rand_ago(30)
        start_ts = created_ts
        end_ts = rand_ago(5) if state == "closed" else ""

        name = random.choice(CS_INCIDENT_NAMES)
        description = (
            f"{name} involving {host_count} host(s). "
            f"Max severity: {severity_display(fine_score)}."
        )

        # Random user list from host domains
        users: list[str] = []
        for hd in hosts_data[:3]:
            users.append(f"{fake.user_name()}@{hd.get('machine_domain', 'acmecorp.internal')}")

        cs_incident_repo.save(CsIncident(
            incident_id=incident_id,
            cid=CS_CID,
            host_ids=chosen_host_ids,
            hosts=hosts_data,
            name=name,
            description=description,
            status=status,
            state=state,
            tags=[],
            fine_score=fine_score,
            start=start_ts,
            end=end_ts,
            created=created_ts,
            modified_timestamp=rand_ago(3),
            assigned_to="" if status == 20 else fake.email(),
            assigned_to_name="" if status == 20 else fake.name(),
            objectives=[f"Falcon Detection Method - {tactics[0]}"] if tactics else [],
            tactics=tactics,
            techniques=techniques,
            users=users,
            lm_host_ids=chosen_host_ids[:2] if host_count > 1 else [],
            lm_hosts_capped=False,
        ))

    return incident_ids
