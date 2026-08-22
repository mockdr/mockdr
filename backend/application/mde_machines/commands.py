"""Microsoft Defender for Endpoint Machine command handlers (mutations)."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict

from domain.event_bus import MdeMachineUpdated, event_bus
from domain.mde_machine import MdeMachine
from domain.mde_machine_action import MdeMachineAction
from repository.mde_machine_action_repo import mde_machine_action_repo
from repository.mde_machine_repo import mde_machine_repo
from utils.dt import utc_now
from utils.mde_fixtures import complete_mde
from utils.mde_serde import to_mde_resource


def _publish_machine_updated(machine: MdeMachine) -> None:
    """Persist a machine and bridge the change into Splunk and Sentinel.

    The bridge subscribed to mde_machine_updated and nothing ever published
    it, so isolating or scanning a machine changed its health status while the
    downstream SIEMs saw nothing (ADR-009).
    """
    mde_machine_repo.save(machine)
    event_bus.publish(
        MdeMachineUpdated(
            entity_id=machine.machineId,
            payload=to_mde_resource(asdict(machine), "machineId"),
            timestamp=time.time(),
        )
    )


def _create_action(
    machine_id: str,
    action_type: str,
    comment: str,
    requestor: str,
) -> dict:
    """Create a machine action record and persist it.

    Args:
        machine_id:  GUID of the target machine.
        action_type: Action type string (e.g. ``"Isolate"``).
        comment:     Operator comment describing the reason.
        requestor:   Identity of the requesting user/application.

    Returns:
        The new machine action as a dict.
    """
    now = utc_now()
    action = MdeMachineAction(
        actionId=str(uuid.uuid4()),
        type=action_type,
        status="Pending",
        machineId=machine_id,
        creationDateTimeUtc=now,
        lastUpdateDateTimeUtc=now,
        requestor=requestor,
        requestorComment=comment,
    )
    mde_machine_action_repo.save(action)
    return complete_mde(to_mde_resource(asdict(action), "actionId"), "machineaction")


def isolate_machine(machine_id: str, body: dict) -> dict | None:
    """Isolate a machine from the network.

    Sets the machine ``healthStatus`` to ``"ImpairedCommunication"`` and creates
    a pending Isolate action.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment`` and optional ``IsolationType``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    machine.healthStatus = "ImpairedCommunication"
    _publish_machine_updated(machine)
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(machine_id, "Isolate", comment, requestor)


def unisolate_machine(machine_id: str, body: dict) -> dict | None:
    """Release a machine from network isolation.

    Restores the machine ``healthStatus`` to ``"Active"``.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    machine.healthStatus = "Active"
    _publish_machine_updated(machine)
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(machine_id, "Unisolate", comment, requestor)


def run_av_scan(machine_id: str, body: dict) -> dict | None:
    """Trigger an antivirus scan on a machine.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment`` and ``ScanType``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(machine_id, "RunAntiVirusScan", comment, requestor)


def restrict_code_execution(machine_id: str, body: dict) -> dict | None:
    """Restrict application execution on a machine.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(machine_id, "RestrictCodeExecution", comment, requestor)


def unrestrict_code_execution(machine_id: str, body: dict) -> dict | None:
    """Remove application execution restriction from a machine.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(machine_id, "UnrestrictCodeExecution", comment, requestor)


def collect_investigation_package(machine_id: str, body: dict) -> dict | None:
    """Collect an investigation package from a machine.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(
        machine_id,
        "CollectInvestigationPackage",
        comment,
        requestor,
    )


def offboard_machine(machine_id: str, body: dict) -> dict | None:
    """Offboard a machine from MDE.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    machine.onboardingStatus = "CanBeOnboarded"
    _publish_machine_updated(machine)
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    return _create_action(machine_id, "Offboard", comment, requestor)


def run_live_response(machine_id: str, body: dict) -> dict | None:
    """Start a live response session on a machine.

    Args:
        machine_id: GUID of the target machine.
        body:       Request body with ``Comment`` and ``Commands``.

    Returns:
        Machine action dict, or None if machine not found.
    """
    machine = mde_machine_repo.get(machine_id)
    if not machine:
        return None
    comment = body.get("Comment", "")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    action = _create_action(machine_id, "RunLiveResponse", comment, requestor)
    # Attach commands to the action if provided
    commands = body.get("Commands", [])
    if commands:
        stored = mde_machine_action_repo.get(action["actionId"])
        if stored:
            stored.commands = commands
            mde_machine_action_repo.save(stored)
            action["commands"] = commands
    return action
