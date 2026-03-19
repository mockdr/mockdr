"""Domain dataclass for Palo Alto Cortex XDR IOC entity."""
from dataclasses import dataclass, field


@dataclass
class XdrIoc:
    """A Cortex XDR indicator of compromise."""

    ioc_id: str
    indicator: str = ""
    type: str = "hash"  # hash / ip / domain_name / url
    severity: str = "medium"
    reputation: str = "unknown"  # good / suspicious / malicious / unknown
    status: str = "enabled"  # enabled / disabled
    expiration_date: int | None = None  # epoch ms
    comment: str = ""
    vendors: list[dict] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.ioc_id
