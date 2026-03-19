"""MDE investigations seeder -- generates automated investigation records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_investigation import MdeInvestigation
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.mde_shared import MDE_INVESTIGATION_STATES, mde_guid
from repository.mde_investigation_repo import mde_investigation_repo
from repository.mde_machine_repo import mde_machine_repo

_STATUS_DETAILS: dict[str, str] = {
    "SuccessfullyRemediated": "All threats were remediated successfully.",
    "Benign": "No malicious activity found. Investigation closed as benign.",
    "Running": "Investigation is currently in progress.",
    "PartiallyRemediated": "Some threats were remediated; manual action needed for remaining items.",
    "TerminatedByUser": "Investigation was manually terminated by an analyst.",
    "Failed": "Investigation encountered errors and could not complete.",
    "Queued": "Investigation is queued and waiting for available resources.",
}


def seed_mde_investigations(
    fake: Faker,
    machine_ids: list[str],
    alert_ids: list[str],
) -> None:
    """Generate approximately 10 automated investigation records.

    Each investigation is linked to a machine and optionally to an alert.
    States are drawn from the weighted ``MDE_INVESTIGATION_STATES`` list.

    Args:
        fake: Shared Faker instance (seeded externally).
        machine_ids: List of ``machineId`` strings to link investigations to.
        alert_ids: List of ``alertId`` strings to use as triggering alerts.
    """
    investigation_count = 10

    # Build a machine_id -> computerDnsName lookup
    all_machines = mde_machine_repo.list_all()
    machine_dns_map: dict[str, str] = {
        m.machineId: m.computerDnsName for m in all_machines
    }

    for i in range(investigation_count):
        investigation_id = mde_guid()
        machine_id = random.choice(machine_ids)
        state = random.choice(MDE_INVESTIGATION_STATES)

        start_time = rand_ago(20)
        # Completed investigations have an end time
        end_time = ""
        if state not in ("Running", "Queued"):
            end_time = rand_ago(5)

        # Use alert_ids cyclically as triggering alerts
        triggering_alert = alert_ids[i % len(alert_ids)] if alert_ids else ""

        computer_dns = machine_dns_map.get(machine_id, "unknown-host")

        mde_investigation_repo.save(MdeInvestigation(
            investigationId=investigation_id,
            startTime=start_time,
            endTime=end_time,
            state=state,
            statusDetails=_STATUS_DETAILS.get(state, ""),
            machineId=machine_id,
            computerDnsName=computer_dns,
            triggeringAlertId=triggering_alert,
        ))
