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
    #: The arguments the client dispatched with, verbatim. splunkd echoes
    #: exactly these back as `request`, and nothing it was not sent.
    request: dict[str, str] = field(default_factory=dict)

    dispatch_state: str = "DONE"
    done_progress: float = 1.0
    event_count: int = 0
    result_count: int = 0
    scan_count: int = 0

    results: list[dict[str, object]] = field(default_factory=list)
    # Pre-transform events. /events must return what the search matched
    # before the pipeline reshaped it, so eventCount can differ from
    # resultCount the way it does in real Splunk.
    events: list[dict[str, object]] = field(default_factory=list)
    messages: list[dict[str, str]] = field(default_factory=list)
    field_list: list[str] = field(default_factory=list)
    #: The same fields as the results envelope describes them: splunkd marks
    #: a group-by column with its rank and top's generated columns with what
    #: they are, and a client rendering a table reads both.
    field_meta: list[dict] = field(default_factory=list)

    ttl: int = 600
    is_saved: bool = False
    is_paused: bool = False
    is_done: bool = True
    is_failed: bool = False

    # When the job was dispatched. This is the origin of the lifecycle clock,
    # so it must not move once set — `touch` extends the TTL, not the search.
    published_at: float = 0.0  # epoch seconds
    # When the TTL countdown last restarted, which is what `touch` updates.
    touched_at: float = 0.0
    # When the job was paused, so unpausing can resume the lifecycle where it
    # stopped rather than jumping ahead by the wall-clock time spent paused.
    paused_at: float = 0.0
    # A control action fixed the reported state (cancel, finalize). A settled
    # job reports what it was told to report, not what the clock would derive.
    settled: bool = False

    @property
    def id(self) -> str:
        """Primary identifier expected by ``Repository[T]``."""
        return self.sid
