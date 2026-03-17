"""In-process event bus for domain event publishing and subscribing.

Thin pub/sub with no external dependencies.  Subscribers register for
event types and receive synchronous callbacks when events are published.
"""
from __future__ import annotations

import logging
import threading
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DomainEvent:
    """Base class for all domain events."""

    event_type: str = ""
    vendor: str = ""
    entity_id: str = ""
    entity_type: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


# ── Concrete event types ───────────────────────────────────────────────────

@dataclass
class ThreatCreated(DomainEvent):
    """Fired when a SentinelOne threat is created."""

    event_type: str = "threat_created"
    vendor: str = "sentinelone"
    entity_type: str = "threat"


@dataclass
class AgentUpdated(DomainEvent):
    """Fired when a SentinelOne agent status changes."""

    event_type: str = "agent_updated"
    vendor: str = "sentinelone"
    entity_type: str = "agent"


@dataclass
class ActivityCreated(DomainEvent):
    """Fired when a SentinelOne activity is logged."""

    event_type: str = "activity_created"
    vendor: str = "sentinelone"
    entity_type: str = "activity"


@dataclass
class CsDetectionCreated(DomainEvent):
    """Fired when a CrowdStrike detection is created."""

    event_type: str = "cs_detection_created"
    vendor: str = "crowdstrike"
    entity_type: str = "detection"


@dataclass
class CsIncidentCreated(DomainEvent):
    """Fired when a CrowdStrike incident is created."""

    event_type: str = "cs_incident_created"
    vendor: str = "crowdstrike"
    entity_type: str = "incident"


@dataclass
class MdeAlertCreated(DomainEvent):
    """Fired when an MDE alert is created."""

    event_type: str = "mde_alert_created"
    vendor: str = "msdefender"
    entity_type: str = "alert"


@dataclass
class MdeMachineUpdated(DomainEvent):
    """Fired when an MDE machine status changes."""

    event_type: str = "mde_machine_updated"
    vendor: str = "msdefender"
    entity_type: str = "machine"


@dataclass
class EsAlertCreated(DomainEvent):
    """Fired when an Elastic Security alert is created."""

    event_type: str = "es_alert_created"
    vendor: str = "elastic"
    entity_type: str = "alert"


@dataclass
class XdrIncidentCreated(DomainEvent):
    """Fired when a Cortex XDR incident is created."""

    event_type: str = "xdr_incident_created"
    vendor: str = "cortex_xdr"
    entity_type: str = "incident"


@dataclass
class XdrAlertCreated(DomainEvent):
    """Fired when a Cortex XDR alert is created."""

    event_type: str = "xdr_alert_created"
    vendor: str = "cortex_xdr"
    entity_type: str = "alert"


# ── Event Bus ──────────────────────────────────────────────────────────────

class EventBus:
    """In-process event bus.  Subscribers register for event types."""

    def __init__(self) -> None:
        """Initialise with empty subscriber registry."""
        self._lock = threading.Lock()
        self._subscribers: dict[str, list[Callable[[DomainEvent], None]]] = defaultdict(list)
        self._global_subscribers: list[Callable[[DomainEvent], None]] = []

    def subscribe(self, event_type: str, handler: Callable[[DomainEvent], None]) -> None:
        """Register a handler for a specific event type.

        Args:
            event_type: The event type string to subscribe to.
            handler:    Callable that receives the domain event.
        """
        with self._lock:
            self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: Callable[[DomainEvent], None]) -> None:
        """Register a handler that receives all events.

        Args:
            handler: Callable that receives any domain event.
        """
        with self._lock:
            self._global_subscribers.append(handler)

    def publish(self, event: DomainEvent) -> None:
        """Publish an event to all matching subscribers.

        Delivery is synchronous — after this call returns, all subscribers
        have processed the event.

        Args:
            event: The domain event to publish.
        """
        with self._lock:
            typed = list(self._subscribers.get(event.event_type, []))
            global_subs = list(self._global_subscribers)
        for handler in typed:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Error in event handler %r for event type %r",
                    handler, event.event_type,
                )
        for handler in global_subs:
            try:
                handler(event)
            except Exception:
                logger.exception(
                    "Error in global event handler %r for event type %r",
                    handler, event.event_type,
                )

    def clear(self) -> None:
        """Remove all subscribers (used by test teardown / reset)."""
        with self._lock:
            self._subscribers.clear()
            self._global_subscribers.clear()


# Module-level singleton
event_bus = EventBus()
