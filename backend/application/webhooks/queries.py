"""Read-only application queries for webhook subscriptions."""
from dataclasses import asdict

from application.webhooks.delivery_log import list_entries as _list_delivery_entries
from repository.webhook_repo import webhook_repo


def list_webhooks() -> dict:
    """Return all webhook subscriptions with secrets masked."""
    return {"data": [_mask_secret(asdict(sub)) for sub in webhook_repo.list_all()]}


def _mask_secret(d: dict) -> dict:
    """Replace the ``secret`` value with a masked version for safe display."""
    if d.get("secret"):
        d["secret"] = "****" + d["secret"][-4:] if len(d["secret"]) >= 4 else "****"
    return d


def get_webhook(webhook_id: str) -> dict | None:
    """Return a single webhook subscription by ID, or None if not found."""
    sub = webhook_repo.get(webhook_id)
    if not sub:
        return None
    return {"data": _mask_secret(asdict(sub))}


def list_deliveries() -> dict:
    """Return recent webhook delivery log entries (newest first).

    Returns:
        Dict with ``data`` list and ``pagination.totalItems``.
    """
    entries = _list_delivery_entries()
    return {
        "data": entries,
        "pagination": {"totalItems": len(entries)},
    }
