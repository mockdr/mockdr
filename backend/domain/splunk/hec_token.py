"""Domain dataclass for a Splunk HTTP Event Collector token."""
from dataclasses import dataclass


@dataclass
class HecToken:
    """An HEC token used to authenticate event ingestion."""

    name: str
    token: str
    index: str = "main"
    indexes: str = ""          # comma-separated allowed indexes
    sourcetype: str = ""
    source: str = ""
    host: str = ""
    disabled: bool = False
    use_ack: bool = False

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.token
