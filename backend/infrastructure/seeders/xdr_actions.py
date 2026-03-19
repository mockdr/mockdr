"""XDR actions seeder -- generates historical response action records."""
from __future__ import annotations

import random

from domain.xdr_action import XdrAction
from infrastructure.seeders.xdr_shared import (
    XDR_ACTION_STATUSES,
    XDR_ACTION_TYPES,
    rand_epoch_ms,
    xdr_id,
)
from repository.xdr_action_repo import xdr_action_repo


def seed_xdr_actions(endpoint_ids: list[str]) -> None:
    """Seed ~15 historical XDR response actions across endpoints.

    Args:
        endpoint_ids: Available endpoint IDs to target actions at.
    """
    count = 15

    for _ in range(count):
        action_type = random.choice(XDR_ACTION_TYPES)
        status = random.choice(XDR_ACTION_STATUSES)
        eid = random.choice(endpoint_ids)

        # Build result based on status
        result: dict | None = None
        if status == "completed":
            result = {"return_value": 0, "message": "Action completed successfully"}
        elif status == "failed":
            result = {"return_value": 1, "message": "Action failed — endpoint unreachable"}

        xdr_action_repo.save(XdrAction(
            action_id=xdr_id("ACT"),
            action_type=action_type,
            status=status,
            endpoint_id=eid,
            result=result,
            creation_time=rand_epoch_ms(60),
        ))
