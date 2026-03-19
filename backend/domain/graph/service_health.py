"""Domain model for Microsoft Graph Service Health."""
from dataclasses import dataclass


@dataclass
class GraphServiceHealth:
    """Represents a service health overview entry."""

    id: str  # noqa: A003 — service name
    service: str = ""
    status: str = "serviceOperational"  # serviceOperational, etc.
    isActive: bool = True  # noqa: N815
