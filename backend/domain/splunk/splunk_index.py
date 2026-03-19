"""Domain dataclass for a Splunk index."""
from dataclasses import dataclass


@dataclass
class SplunkIndex:
    """A Splunk index with basic metadata."""

    name: str
    total_event_count: int = 0
    current_db_size_mb: float = 0.0
    max_data_size: str = "auto_high_volume"
    frozen_time_period_in_secs: int = 188697600  # ~6 years
    disabled: bool = False
    data_type: str = "event"   # event | metric
    min_time: str = ""
    max_time: str = ""

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.name
