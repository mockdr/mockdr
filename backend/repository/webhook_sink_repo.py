"""Repository for WebhookSinkEntry records backed by InMemoryStore."""
from __future__ import annotations

from dataclasses import asdict

from domain.webhook_sink_entry import WebhookSinkEntry
from repository.store import store


class WebhookSinkRepository:
    """Append-only repository for captured webhook deliveries.

    Does not subclass ``Repository[T]`` because no ``save``/``delete``/``get``
    semantics are needed — only append and list operations.
    """

    def append(self, entry: WebhookSinkEntry) -> None:
        """Persist a new webhook sink entry at the head of the log.

        Args:
            entry: The ``WebhookSinkEntry`` to persist.
        """
        store.append_webhook_sink(entry.id, asdict(entry))

    def list_recent(self) -> list[WebhookSinkEntry]:
        """Return all webhook sink entries in newest-first order.

        Returns:
            List of ``WebhookSinkEntry`` instances ordered newest-first.
        """
        return [WebhookSinkEntry(**record) for record in store.list_webhook_sink()]

    def clear(self) -> None:
        """Remove all webhook sink entries from the store."""
        store.clear_webhook_sink()


webhook_sink_repo = WebhookSinkRepository()
