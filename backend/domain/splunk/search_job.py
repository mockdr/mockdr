"""Domain dataclass for a Splunk search job."""
from dataclasses import dataclass, field


@dataclass
class SearchJob:
    """A Splunk search job tracking SPL execution state and results.

    Lifecycle: QUEUED → PARSING → RUNNING → FINALIZING → DONE | FAILED
    """

    sid: str
    search: str = ""
    earliest_time: str = ""
    latest_time: str = ""
    status_buckets: int = 0
    exec_mode: str = "normal"  # normal | blocking | oneshot

    dispatch_state: str = "DONE"
    done_progress: float = 1.0
    event_count: int = 0
    result_count: int = 0
    scan_count: int = 0

    results: list[dict[str, object]] = field(default_factory=list)
    messages: list[dict[str, str]] = field(default_factory=list)
    field_list: list[str] = field(default_factory=list)

    ttl: int = 600
    is_saved: bool = False
    is_paused: bool = False
    is_done: bool = True
    is_failed: bool = False

    published_at: float = 0.0  # epoch seconds

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.sid
