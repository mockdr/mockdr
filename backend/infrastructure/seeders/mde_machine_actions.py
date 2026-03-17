"""MDE machine actions seeder -- generates historical completed action records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_machine_action import MdeMachineAction
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.mde_shared import MDE_MACHINE_ACTION_TYPES, mde_guid
from repository.mde_machine_action_repo import mde_machine_action_repo

_REQUEST_COMMENTS: list[str] = [
    "Isolating endpoint due to active malware infection.",
    "Running full AV scan after suspicious activity alert.",
    "Collecting investigation package for forensic analysis.",
    "Restricting code execution during incident response.",
    "Unisolating endpoint after remediation confirmed.",
    "Routine scheduled scan initiated by SOC.",
    "Unrestricting code execution post-investigation.",
]


def seed_mde_machine_actions(
    fake: Faker,
    machine_ids: list[str],
) -> None:
    """Generate approximately 15 historical completed machine actions.

    All seeded actions have ``status="Succeeded"`` to represent historical
    actions that have already completed.

    Args:
        fake: Shared Faker instance (seeded externally).
        machine_ids: List of ``machineId`` strings to associate actions with.
    """
    action_count = 15

    for _ in range(action_count):
        action_id = mde_guid()
        machine_id = random.choice(machine_ids)
        action_type = random.choice(MDE_MACHINE_ACTION_TYPES)
        creation_time = rand_ago(30)
        last_update = rand_ago(5)

        scope = "Full"
        if action_type == "RunAntiVirusScan":
            scope = random.choice(["Full", "Quick"])

        mde_machine_action_repo.save(MdeMachineAction(
            actionId=action_id,
            type=action_type,
            status="Succeeded",
            machineId=machine_id,
            creationDateTimeUtc=creation_time,
            lastUpdateDateTimeUtc=last_update,
            requestor=fake.email(),
            requestorComment=random.choice(_REQUEST_COMMENTS),
            scope=scope,
        ))
