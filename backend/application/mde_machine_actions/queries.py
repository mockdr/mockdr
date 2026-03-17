"""Microsoft Defender for Endpoint Machine Action query handlers (read-only)."""
from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from repository.mde_machine_action_repo import mde_machine_action_repo
from utils.dt import utc_now
from utils.mde_odata import apply_odata_filter, apply_odata_orderby
from utils.mde_response import build_mde_list_response


def _auto_promote(action_dict: dict) -> dict:
    """Auto-promote Pending actions to Succeeded after 1 second.

    MDE actions are async; this simulates completion for test tooling.

    Args:
        action_dict: Machine action dict to potentially promote.

    Returns:
        The action dict, possibly with status updated to ``"Succeeded"``.
    """
    if action_dict.get("status") != "Pending":
        return action_dict
    created = action_dict.get("creationDateTimeUtc", "")
    if not created:
        return action_dict
    try:
        created_dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC,
        )
        if (datetime.now(UTC) - created_dt).total_seconds() > 1.0:
            action_dict["status"] = "Succeeded"
            action_dict["lastUpdateDateTimeUtc"] = utc_now()
            # Persist the promotion
            stored = mde_machine_action_repo.get(action_dict["actionId"])
            if stored:
                stored.status = "Succeeded"
                stored.lastUpdateDateTimeUtc = action_dict["lastUpdateDateTimeUtc"]
                mde_machine_action_repo.save(stored)
    except (ValueError, TypeError):
        pass
    return action_dict


def list_machine_actions(
    filter_str: str | None,
    top: int,
    skip: int,
    orderby: str | None,
) -> dict:
    """List machine actions with OData filtering, ordering, and pagination.

    Pending actions older than 1 second are automatically promoted to
    Succeeded to simulate async completion.

    Args:
        filter_str: OData ``$filter`` expression, or None for all actions.
        top:        Maximum number of records to return (``$top``).
        skip:       Number of records to skip (``$skip``).
        orderby:    OData ``$orderby`` expression, or None.

    Returns:
        OData list response with paginated machine action records.
    """
    records = [_auto_promote(asdict(a)) for a in mde_machine_action_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    next_link = None
    if skip + top < total:
        next_link = (
            f"https://api.securitycenter.microsoft.com/api/machineactions"
            f"?$top={top}&$skip={skip + top}"
        )
    return build_mde_list_response(page, next_link=next_link)


def get_machine_action(action_id: str) -> dict | None:
    """Get a single machine action by its action ID, with auto-promotion.

    Args:
        action_id: The GUID of the machine action.

    Returns:
        Machine action dict, or None if not found.
    """
    action = mde_machine_action_repo.get(action_id)
    if not action:
        return None
    return _auto_promote(asdict(action))


def get_package_uri(action_id: str) -> dict | None:
    """Get the download URI for a collected investigation package.

    Returns a mock download URI matching MDE API format.

    Args:
        action_id: The GUID of the CollectInvestigationPackage action.

    Returns:
        Dict with ``value`` containing the download URL, or None if action
        not found.
    """
    action = mde_machine_action_repo.get(action_id)
    if not action:
        return None
    return {
        "value": (
            f"https://api.securitycenter.microsoft.com/api/machineactions/"
            f"{action_id}/GetPackageUri/mock-investigation-package.zip"
        ),
    }
