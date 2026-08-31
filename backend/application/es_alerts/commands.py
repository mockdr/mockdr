"""Elastic Security alert command handlers (mutations)."""
from __future__ import annotations

from application import bridge
from repository.es_alert_repo import es_alert_repo
from utils.es_ecs import to_ecs_document
from utils.es_query import filter_es_records
from utils.serde import record_dict


def update_alert_status(alert_ids: list[str], status: str) -> dict:
    """Update the workflow status of one or more alerts.

    Args:
        alert_ids: List of alert IDs to update.
        status:    New status — ``"open"``, ``"acknowledged"``, or ``"closed"``.

    Returns:
        The Elasticsearch ``update_by_query`` response Kibana proxies back.
    """
    updated = 0
    for alert_id in alert_ids:
        alert = es_alert_repo.get(alert_id)
        if alert:
            alert.workflow_status = status
            alert.signal_status = status
            es_alert_repo.save(alert)
            bridge.es_alert_changed(alert)
            updated += 1
    # Kibana proxies Elasticsearch's update_by_query and returns its whole
    # response; `{"updated": N}` alone left a client with nothing to check for
    # version conflicts or failures.
    return _update_by_query_response(updated)


def update_alert_status_by_query(query: dict, status: str) -> dict:
    """Set the status of every alert a query matches.

    The route validated this arm of the body and then handed only
    `signal_ids` to the command, so a client that selected alerts the way
    Kibana's own UI selects them — by query — was told `updated: 0` for a
    query matching 45 alerts, and nothing changed.  A bulk status change
    that silently does nothing is the worst kind: the operator moves on.
    """
    index = ".siem-signals-default"
    alerts = list(es_alert_repo.list_all())
    documents = [to_ecs_document(record_dict(a), index) for a in alerts]
    # `apply_es_query` returns the same dict objects it was given, so the
    # surviving documents identify their alerts by identity rather than by
    # a field the ECS mapping may have moved or renamed.
    by_identity = {id(doc): alert.id for doc, alert in zip(documents, alerts, strict=True)}
    # Every match, not the first page: update_by_query has no size.
    matched = filter_es_records(documents, {"query": query})
    return update_alert_status(
        [by_identity[id(doc)] for doc in matched if id(doc) in by_identity], status,
    )


def _update_by_query_response(updated: int, *, took: int = 5) -> dict:
    """Build the ``update_by_query`` envelope Kibana returns for signal writes."""
    return {
        "took": took,
        "timed_out": False,
        "total": updated,
        "updated": updated,
        "deleted": 0,
        "batches": 1 if updated else 0,
        "version_conflicts": 0,
        "noops": 0,
        "retries": {"bulk": 0, "search": 0},
        "throttled_millis": 0,
        "requests_per_second": -1.0,
        "throttled_until_millis": 0,
        "failures": [],
    }


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
            bridge.es_alert_changed(alert)
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
            bridge.es_alert_changed(alert)
            updated += 1
    return {"updated": updated}
