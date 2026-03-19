"""Domain dataclass for CrowdStrike Falcon Detection entities."""
from dataclasses import dataclass, field


@dataclass
class CsDetection:
    """A CrowdStrike Falcon detection (alert).

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    The ``id`` property aliases ``composite_id`` so the generic Repository[T]
    pattern works unchanged.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    composite_id: str

    # ── Nested device snapshot ────────────────────────────────────────────────
    device: dict = field(default_factory=dict)

    # ── Behaviors ─────────────────────────────────────────────────────────────
    behaviors: list[dict] = field(default_factory=list)

    # ── Severity / Confidence ─────────────────────────────────────────────────
    max_severity: int = 0
    max_severity_displayname: str = "Informational"
    max_confidence: int = 0

    # ── Status / Workflow ─────────────────────────────────────────────────────
    status: str = "new"
    show_in_ui: bool = True

    # ── Timestamps ────────────────────────────────────────────────────────────
    created_timestamp: str = ""
    first_behavior: str = ""
    last_behavior: str = ""
    date_updated: str = ""

    # ── Assignment ────────────────────────────────────────────────────────────
    assigned_to_name: str = ""
    assigned_to_uid: str = ""

    # ── Triage metrics ────────────────────────────────────────────────────────
    seconds_to_triaged: int = 0
    seconds_to_resolved: int = 0

    # ── Host info ─────────────────────────────────────────────────────────────
    hostinfo: dict = field(default_factory=dict)

    # ── Notification ──────────────────────────────────────────────────────────
    email_sent: bool = False

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.composite_id
