"""Microsoft Defender for Endpoint User-related query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict

from repository.mde_alert_repo import mde_alert_repo
from repository.mde_machine_repo import mde_machine_repo
from utils.mde_response import build_mde_list_response


def get_user_machines(user_id: str) -> dict:
    r"""Get machines where a specific user has logged on.

    Searches all machines for the given user ID in their ``loggedOnUsers``
    list.

    Args:
        user_id: The user identifier (e.g. ``domain\username`` or UPN).

    Returns:
        OData list response with machine records.
    """
    machines = mde_machine_repo.list_all()
    matched = []
    for machine in machines:
        for user in machine.loggedOnUsers:
            acct = user.get("accountName", "").lower()
            domain = user.get("accountDomain", "").lower()
            if (
                acct == user_id.lower()
                or f"{domain}\\{acct}" == user_id.lower()
            ):
                matched.append(asdict(machine))
                break
    return build_mde_list_response(matched)


def get_user_alerts(user_id: str) -> dict:
    r"""Get alerts for machines where a specific user has logged on.

    First finds all machines associated with the user, then retrieves
    all alerts for those machines.

    Args:
        user_id: The user identifier (e.g. ``domain\username`` or UPN).

    Returns:
        OData list response with alert records.
    """
    # Find machine IDs associated with this user
    machines = mde_machine_repo.list_all()
    machine_ids: set[str] = set()
    for machine in machines:
        for user in machine.loggedOnUsers:
            acct = user.get("accountName", "").lower()
            domain = user.get("accountDomain", "").lower()
            if (
                acct == user_id.lower()
                or f"{domain}\\{acct}" == user_id.lower()
            ):
                machine_ids.add(machine.machineId)
                break

    # Collect alerts for those machines
    alerts: list[dict] = []
    for machine_id in machine_ids:
        machine_alerts = mde_alert_repo.get_by_machine_id(machine_id)
        alerts.extend(asdict(a) for a in machine_alerts)
    return build_mde_list_response(alerts)
