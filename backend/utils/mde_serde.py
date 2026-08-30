"""Primary-key naming for Microsoft Defender for Endpoint resources.

Every MDE resource is addressed by ``id``. The stored dataclasses name the
primary key after the resource — ``machineId``, ``alertId``, ``actionId``,
``investigationId``, ``indicatorId`` — so a client written against the real
API read ``undefined`` for the one field it needs to follow a link or issue a
follow-up call.

Only the *primary* key is renamed. The foreign keys are already correct: an
alert genuinely carries ``machineId`` and ``incidentId``, and an investigation
genuinely carries ``triggeringAlertId``. Those are separate fields and are
left alone.
"""
from __future__ import annotations

from typing import Any

__all__ = ["to_mde_resource"]


def to_mde_resource(record: dict[str, Any], primary_key: str) -> dict[str, Any]:
    """Return *record* with *primary_key* renamed to ``id``, in place.

    The resource-specific spelling is dropped, because on the resource itself
    it is the primary key rather than a link to anything — a real machine
    document has ``id`` and no ``machineId``.
    """
    if primary_key == "id" or primary_key not in record:
        return record

    return {
        ("id" if key == primary_key else key): value
        for key, value in record.items()
    }

def machine_name(machine_id: str) -> str:
    """The DNS name of the machine an id names, or an empty string.

    An alert, an investigation and a machine action all carry
    `computerDnsName` beside `machineId` in Defender's own property tables,
    and this mock set it on none of them — so a client reading any of the
    three to find the affected host got an empty string while
    `/api/machines` had the name all along.
    """
    from repository.mde_machine_repo import mde_machine_repo  # noqa: PLC0415

    machine = mde_machine_repo.get(str(machine_id or ""))
    return str(getattr(machine, "computerDnsName", "") or "") if machine else ""
