"""Elastic Security alert command handlers (mutations)."""
from __future__ import annotations

from repository.es_alert_repo import es_alert_repo


def update_alert_status(alert_ids: list[str], status: str) -> dict:
    """Update the workflow status of one or more alerts.

    Args:
        alert_ids: List of alert IDs to update.
        status:    New status — ``"open"``, ``"acknowledged"``, or ``"closed"``.

    Returns:
        Summary dict with updated count.
    """
    updated = 0
    for alert_id in alert_ids:
        alert = es_alert_repo.get(alert_id)
        if alert:
            alert.workflow_status = status
            alert.signal_status = status
            es_alert_repo.save(alert)
            updated += 1
    return {"updated": updated}


def update_alert_tags(
    alert_ids: list[str],
    tags_to_add: list[str] | None = None,
    tags_to_remove: list[str] | None = None,
) -> dict:
    """Add and/or remove tags on one or more alerts.

    Args:
        alert_ids:      List of alert IDs to update.
        tags_to_add:    Tags to add (skips duplicates).
        tags_to_remove: Tags to remove (ignores missing).

    Returns:
        Summary dict with updated count.
    """
    add = tags_to_add or []
    remove = set(tags_to_remove or [])
    updated = 0
    for alert_id in alert_ids:
        alert = es_alert_repo.get(alert_id)
        if alert:
            existing = set(alert.tags)
            existing -= remove
            existing.update(add)
            alert.tags = sorted(existing)
            es_alert_repo.save(alert)
            updated += 1
    return {"updated": updated}


def update_alert_assignees(
    alert_ids: list[str],
    assignees_to_add: list[dict] | None = None,
    assignees_to_remove: list[dict] | None = None,
) -> dict:
    """Add and/or remove assignees on one or more alerts.

    Args:
        alert_ids:           List of alert IDs to update.
        assignees_to_add:    Assignee objects to add.
        assignees_to_remove: Assignee objects to remove (by uid match).

    Returns:
        Summary dict with updated count.
    """
    add = assignees_to_add or []
    remove_uids = {a.get("uid") for a in (assignees_to_remove or []) if a.get("uid")}
    updated = 0
    for alert_id in alert_ids:
        alert = es_alert_repo.get(alert_id)
        if alert:
            existing = [a for a in alert.assignees if a.get("uid") not in remove_uids]
            existing_uids = {a.get("uid") for a in existing}
            for assignee in add:
                if assignee.get("uid") not in existing_uids:
                    existing.append(assignee)
                    existing_uids.add(assignee.get("uid"))
            alert.assignees = existing
            es_alert_repo.save(alert)
            updated += 1
    return {"updated": updated}
