"""Microsoft Defender for Endpoint Machine Action query handlers (read-only)."""

from __future__ import annotations

from datetime import UTC, datetime

from application import settling
from repository.mde_machine_action_repo import mde_machine_action_repo
from utils.mde_fixtures import complete_mde
from utils.mde_odata import apply_odata_filter, apply_odata_orderby
from utils.mde_response import build_mde_list_response, mde_context
from utils.mde_serde import to_mde_resource
from utils.odata_paging import page_link
from utils.serde import record_dict


def _resource(record: dict) -> dict:
    """Render a stored record as the API resource, keyed by ``id``."""
    return complete_mde(to_mde_resource(record, "actionId"), "machineaction")


#: The state an action is in until Defender has carried it out.
_PENDING = "Pending"


def settled(action: object) -> object:
    """Complete a Pending action once Defender has had time to carry it out.

    MDE actions are async; this simulates completion for test tooling. The
    action completes about a second after it was created whether or not
    anyone reads it, so ``lastUpdateDateTimeUtc`` says *then*: stamped at
    the read that noticed, an action left unread for a day reported a day's
    run time, and its completion moved with whoever looked first.

    Args:
        action: The stored machine action.

    Returns:
        The action, ``Succeeded`` if its time has come.
    """
    if getattr(action, "status", None) != _PENDING:
        return action
    created = getattr(action, "creationDateTimeUtc", "") or ""
    try:
        created_dt = datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=UTC,
        )
    except (ValueError, TypeError):
        return action
    if not settling.has_answered((datetime.now(UTC) - created_dt).total_seconds()):
        return action
    action.status = "Succeeded"  # type: ignore[attr-defined]
    action.lastUpdateDateTimeUtc = settling.answered_at(created)  # type: ignore[attr-defined]
    mde_machine_action_repo.save(action)  # type: ignore[arg-type]
    return action


def settle_due() -> int:
    """Complete every pending action Defender would have finished; how many."""
    return settling.settle_each(
        mde_machine_action_repo.list_all(), "status", {_PENDING}, settled,
    )


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
    records = [_resource(record_dict(settled(a))) for a in mde_machine_action_repo.list_all()]
    if filter_str:
        records = apply_odata_filter(records, filter_str)
    records = apply_odata_orderby(records, orderby)
    total = len(records)
    page = records[skip : skip + top]
    next_link = page_link(
        skip + top, total,
        fallback=f"https://api.security.microsoft.com/api/machineactions?$top={top}",
    )
    return build_mde_list_response(page, context=mde_context("MachineActions"),
                                   next_link=next_link)


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
    return _resource(record_dict(settled(action)))


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
