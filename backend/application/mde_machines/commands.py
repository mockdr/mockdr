"""Microsoft Defender for Endpoint Machine command handlers (mutations)."""

from __future__ import annotations

import time
import uuid

from domain.event_bus import MdeMachineUpdated, event_bus
from domain.mde_machine import MdeMachine
from domain.mde_machine_action import MdeMachineAction
from repository.mde_machine_action_repo import mde_machine_action_repo
from repository.mde_machine_repo import mde_machine_repo
from utils.dt import utc_now
from utils.mde_fixtures import complete_mde
from utils.mde_serde import machine_name, to_mde_resource
from utils.serde import record_dict


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
            payload=to_mde_resource(record_dict(machine), "machineId"),
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
        computerDnsName=machine_name(machine_id),
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
    return complete_mde(to_mde_resource(record_dict(action), "actionId"), "machineaction")


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


class InvalidMachineUpdateError(ValueError):
    """A machine change MDE would refuse."""


#: What MDE says a device is worth. The API refuses anything else.
DEVICE_VALUES = ("Normal", "Low", "High")


def update_machine(machine_id: str, body: dict) -> dict | None:
    """Set a machine's tags or its device value, and answer the machine back.

    MDE documents `machineTags` and `deviceValue` on this call and answers
    the updated machine. mockdr served the six action routes under this
    machine and answered 405 to the one that changes the machine itself.

    Args:
        machine_id: The GUID of the machine.
        body: The request body.

    Returns:
        The updated machine as MDE renders it, or None if there is no such
        machine.

    Raises:
        InvalidMachineUpdateError: A member is of the wrong shape, or names a
            device value MDE does not have.
    """
    machine = mde_machine_repo.get(machine_id)
    if machine is None:
        return None

    if "machineTags" in body:
        tags = body["machineTags"]
        if not isinstance(tags, list) or not all(isinstance(tag, str) for tag in tags):
            msg = "machineTags must be a list of strings"
            raise InvalidMachineUpdateError(msg)
        machine.machineTags = list(tags)

    if "deviceValue" in body:
        value = body["deviceValue"]
        if value not in DEVICE_VALUES:
            msg = f"deviceValue must be one of {', '.join(DEVICE_VALUES)}"
            raise InvalidMachineUpdateError(msg)
        machine.deviceValue = value

    mde_machine_repo.save(machine)
    _publish_machine_updated(machine)
    # The same rendering the GET beside it uses, so the two agree.
    from application.mde_machines.queries import resource  # noqa: PLC0415

    return resource(record_dict(machine))
