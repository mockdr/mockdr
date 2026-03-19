"""Repository for WebhookSubscription entities."""
from domain.webhook import WebhookSubscription
from repository.base import Repository


class WebhookRepository(Repository[WebhookSubscription]):
    """Repository for WebhookSubscription entities backed by the global store."""

    def __init__(self) -> None:
        """Initialise the repository bound to the webhook_subscriptions collection."""
        super().__init__("webhook_subscriptions")

    def get_active_for_event(self, event_type: str) -> list[WebhookSubscription]:
        """Return all active subscriptions that include the given event type.

        Args:
            event_type: The event type string to match, e.g. ``"threat.updated"``.

        Returns:
            List of active ``WebhookSubscription`` instances for the event type.
        """
        return [
            sub
            for sub in self.list_all()
            if sub.active and event_type in sub.eventTypes
        ]


webhook_repo = WebhookRepository()
