"""Domain dataclass for a Splunk saved search."""
from dataclasses import dataclass, field


@dataclass
class SavedSearch:
    """A Splunk saved search / report / alert."""

    name: str
    search: str = ""
    description: str = ""

    cron_schedule: str = "*/5 * * * *"
    is_scheduled: bool = False
    disabled: bool = False

    dispatch_earliest_time: str = "-24h@h"
    dispatch_latest_time: str = "now"

    alert_type: str = "number of events"
    alert_comparator: str = "greater than"
    alert_threshold: str = "0"

    actions: str = ""  # comma-separated action names
    action_email_to: str = ""

    # Dispatch history (list of sids)
    history: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.name
