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


class MachineActionError(ValueError):
    """A machine-action request Defender refuses with ``400``.

    Carries the Defender error code alongside the message, because the two
    refusals here are told apart by code: ``MissingRequiredParameter`` and
    ``InvalidRequestBody`` are both listed in
    https://learn.microsoft.com/en-us/defender-endpoint/api/common-errors, as
    is ``ActiveRequestAlreadyExists``'s status (see :func:`_refuse_if_pending`).
    """

    def __init__(self, code: str, message: str) -> None:
        """Keep the Defender error code beside the message."""
        super().__init__(message)
        self.code = code


def _require_comment(body: dict) -> str:
    """The action's ``Comment``, which every action page marks Required.

    The mock read it with ``body.get("Comment", "")``, so an action without a
    reason -- or with ``comment`` in the wrong case, which Defender does not
    recognise ("The submitted body parameters are currently case-sensitive",
    common-errors) -- was accepted with an empty comment.

    Raises:
        MachineActionError: ``MissingRequiredParameter`` when absent or empty.
    """
    comment = body.get("Comment")
    if not isinstance(comment, str) or not comment.strip():
        raise MachineActionError("MissingRequiredParameter", "Parameter Comment is missing.")
    return comment


def _choice(body: dict, key: str, allowed: tuple[str, ...], *, required: bool) -> str | None:
    """A body member restricted to the values its action page lists.

    Raises:
        MachineActionError: ``MissingRequiredParameter`` when a required one
            is absent, ``InvalidRequestBody`` when the value is not listed.
    """
    value = body.get(key)
    if value is None:
        if required:
            raise MachineActionError("MissingRequiredParameter", f"Parameter {key} is missing.")
        return None
    if value not in allowed:
        raise MachineActionError(
            "InvalidRequestBody",
            f"Invalid request body. {key} must be one of {', '.join(allowed)}.",
        )
    return str(value)


def _refuse_if_pending(machine_id: str, action_type: str) -> None:
    """Refuse a second action of a type while the first is still pending.

    Defender documents it for these actions: "If you send multiple API calls
    to ... for the same device, it returns 'pending machine action' or HTTP
    400 with the message 'Action is already in progress'" (unisolate,
    runAntiVirusScan, restrictCodeExecution, unrestrictCodeExecution pages);
    "If a collection is already running, this returns 400 Bad Request"
    (collectInvestigationPackage); and for live response "subsequent requests
    are responded to with HTTP 400 - ActiveRequestAlreadyExists"
    (run-live-response). The code is the one the live-response page names;
    the other pages give only the status and the message. The mock queued
    any number of identical actions.

    Pending is judged the way the action listing judges it: an action is
    promoted to Succeeded a second after it was created (see
    ``application/mde_machine_actions/queries.py``).

    Raises:
        MachineActionError: ``ActiveRequestAlreadyExists``.
    """
    from application.mde_machine_actions.queries import _auto_promote  # noqa: PLC0415

    for action in mde_machine_action_repo.list_all():
        if action.machineId != machine_id or action.type != action_type:
            continue
        if _auto_promote(record_dict(action)).get("status") == "Pending":
            raise MachineActionError("ActiveRequestAlreadyExists", "Action is already in progress")


#: The values each action page lists.
ISOLATION_TYPES = ("Full", "Selective", "UnManagedDevice")
SCAN_TYPES = ("Quick", "Full")


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
    comment = _require_comment(body)
    _choice(body, "IsolationType", ISOLATION_TYPES, required=False)
    machine.healthStatus = "ImpairedCommunication"
    _publish_machine_updated(machine)
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
    comment = _require_comment(body)
    _refuse_if_pending(machine_id, "Unisolate")
    machine.healthStatus = "Active"
    _publish_machine_updated(machine)
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
    comment = _require_comment(body)
    _choice(body, "ScanType", SCAN_TYPES, required=True)
    _refuse_if_pending(machine_id, "RunAntiVirusScan")
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
    comment = _require_comment(body)
    _refuse_if_pending(machine_id, "RestrictCodeExecution")
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
    comment = _require_comment(body)
    _refuse_if_pending(machine_id, "UnrestrictCodeExecution")
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
    comment = _require_comment(body)
    _refuse_if_pending(machine_id, "CollectInvestigationPackage")
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
    comment = _require_comment(body)
    machine.onboardingStatus = "CanBeOnboarded"
    _publish_machine_updated(machine)
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
    _refuse_if_pending(machine_id, "RunLiveResponse")
    requestor = body.get("Requestor", "analyst@acmecorp.internal")
    action = _create_action(machine_id, "RunLiveResponse", comment, requestor)
    # Attach commands to the action if provided
    commands = body.get("Commands", [])
    if commands:
        # The resource is keyed `id` (to_mde_resource); `actionId` was a
        # KeyError, so every live response that carried commands answered 500.
        stored = mde_machine_action_repo.get(action["id"])
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
