"""Domain dataclass for Palo Alto Cortex XDR Distribution (agent package) entity."""
from dataclasses import dataclass


@dataclass
class XdrDistribution:
    """A Cortex XDR agent distribution package."""

    distribution_id: str
    name: str = ""
    platform: str = ""
    package_type: str = ""
    status: str = "ready"
    agent_version: str = ""
    creation_timestamp: int = 0  # epoch ms

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.distribution_id
