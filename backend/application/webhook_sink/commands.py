"""Write-only application commands for the webhook sink."""
from __future__ import annotations

from dataclasses import asdict

from domain.webhook_sink_entry import WebhookSinkEntry
from repository.webhook_sink_repo import webhook_sink_repo
from utils.dt import utc_now
from utils.id_gen import new_id


def capture_webhook(event_type: str, headers: dict, body: dict) -> dict:
    """Record an incoming webhook delivery in the sink.

    Args:
        event_type: The value of the ``X-S1-Webhook-Event`` header (or empty).
        headers: Raw HTTP headers from the delivery.
        body: Parsed JSON body of the delivery.

    Returns:
        Dict with ``data`` containing the persisted entry.
    """
    entry = WebhookSinkEntry(
        id=new_id(),
        received_at=utc_now(),
        event_type=event_type,
        headers=headers,
        body=body,
    )
    webhook_sink_repo.append(entry)
    return {"data": asdict(entry)}


def clear_sink() -> dict:
    """Delete all captured webhook deliveries.

    Returns:
        Dict with ``data.affected`` indicating the number of deleted entries.
    """
    affected = len(webhook_sink_repo.list_recent())
    webhook_sink_repo.clear()
    return {"data": {"affected": affected}}
