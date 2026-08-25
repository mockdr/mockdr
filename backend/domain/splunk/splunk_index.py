"""Domain dataclass for a Splunk index."""
import dataclasses
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

    #: What a client set through ``POST /services/data/indexes`` (or the edit
    #: route), by the argument names splunkd accepts. Creation used to keep
    #: the name and drop every setting beside it, so an index made with
    #: ``maxTotalDataSizeMB=12345`` read back as the default 500000.
    settings: dict[str, object] = dataclasses.field(default_factory=dict)

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.name
