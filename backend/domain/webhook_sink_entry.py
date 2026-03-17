from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WebhookSinkEntry:
    """A single webhook delivery captured by the built-in sink."""

    id: str
    received_at: str
    event_type: str
    headers: dict[str, str] = field(default_factory=dict)
    body: dict = field(default_factory=dict)
