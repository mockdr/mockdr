"""MDE investigations seeder -- generates automated investigation records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_investigation import MdeInvestigation
from infrastructure.seeders._shared import rand_after, rand_ago
from infrastructure.seeders.mde_shared import MDE_INVESTIGATION_STATES
from repository.mde_alert_repo import mde_alert_repo
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


#: How many of the tenant's alerts triggered an automated investigation.
_INVESTIGATION_COUNT = 10


def seed_mde_investigations(
    fake: Faker,
    machine_ids: list[str],
    alert_ids: list[str],
) -> None:
    """Generate the automated investigations the tenant's alerts triggered.

    An investigation is what an alert set off, so each one here is built
    from an alert this install has: the alert's machine, and the alert's id
    as ``triggeringAlertId``. The alert is given the investigation's id back,
    which is what makes `/api/investigations/{id}` answer for the id an alert
    reports — it used to be a `random.randint`, so it never did.

    Defender numbers its investigations rather than naming them with a GUID:
    the Splunk add-on's own sample declares ``investigationId`` a number, and
    the alert field that carries it is one.

    Args:
        fake: Shared Faker instance (seeded externally).
        machine_ids: Machines this tenant has, used when an alert names none.
        alert_ids: The alert ids this install seeded, in order.
    """
    triggering = alert_ids[:_INVESTIGATION_COUNT]

    for number, alert_id in enumerate(triggering, start=1):
        alert = mde_alert_repo.get(alert_id)
        if alert is None:  # pragma: no cover - the seeder just wrote them
            continue

        state = random.choice(MDE_INVESTIGATION_STATES)
        start_time = rand_ago(20)
        # Completed investigations have an end time — after they started,
        # which a second independent draw did not guarantee: two of them
        # ended before they began.
        end_time = "" if state in ("Running", "Queued") else rand_after(start_time, 20)
        machine_id = alert.machineId or random.choice(machine_ids)
        machine = mde_machine_repo.get(machine_id)

        mde_investigation_repo.save(MdeInvestigation(
            investigationId=str(number),
            startTime=start_time,
            endTime=end_time,
            state=state,
            statusDetails=_STATUS_DETAILS.get(state, ""),
            machineId=machine_id,
            computerDnsName=machine.computerDnsName if machine else "",
            triggeringAlertId=alert_id,
        ))

        # The alert reports the investigation it set off, and the state that
        # investigation is actually in.
        alert.investigationId = number
        alert.investigationState = state
        mde_alert_repo.save(alert)
