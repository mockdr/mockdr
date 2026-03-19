"""Domain dataclass and constants for webhook subscriptions."""
from dataclasses import dataclass, field

THREAT_CREATED = "threat.created"
THREAT_UPDATED = "threat.updated"
ALERT_CREATED = "alert.created"
ALERT_UPDATED = "alert.updated"
AGENT_OFFLINE = "agent.offline"
AGENT_INFECTED = "agent.infected"

ALL_EVENT_TYPES = {
    THREAT_CREATED,
    THREAT_UPDATED,
    ALERT_CREATED,
    ALERT_UPDATED,
    AGENT_OFFLINE,
    AGENT_INFECTED,
}


@dataclass
class WebhookSubscription:
    """Represents a webhook subscription that receives event notifications.

    Attributes:
        id: Unique identifier for this subscription.
        url: Destination URL to POST events to.
        eventTypes: List of event type strings to subscribe to,
            e.g. ``["threat.created", "agent.offline"]``.
        secret: HMAC-SHA256 signing secret.  Empty string means no signing.
        active: Whether this subscription is currently active.
        description: Human-readable description of this subscription.
        createdAt: ISO 8601 creation timestamp.
        updatedAt: ISO 8601 last-update timestamp.
    """

    id: str
    url: str
    eventTypes: list = field(default_factory=list)
    secret: str = ""
    active: bool = True
    description: str = ""
    createdAt: str = ""
    updatedAt: str = ""
