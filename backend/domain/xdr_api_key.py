"""Domain dataclass for Palo Alto Cortex XDR API Key entity."""
from dataclasses import dataclass


@dataclass
class XdrApiKey:
    """A Cortex XDR API key credential."""

    key_id: str
    key_secret: str = ""
    name: str = ""
    role: str = "viewer"  # admin / analyst / viewer

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.key_id
