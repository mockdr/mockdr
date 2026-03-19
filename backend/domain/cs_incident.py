"""Domain dataclass for CrowdStrike Falcon Incident entities."""
from dataclasses import dataclass, field


@dataclass
class CsIncident:
    """A CrowdStrike Falcon incident.

    Field names match the real CrowdStrike Falcon API exactly (snake_case).
    The ``id`` property aliases ``incident_id`` so the generic Repository[T]
    pattern works unchanged.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    incident_id: str
    cid: str

    # ── Hosts ─────────────────────────────────────────────────────────────────
    host_ids: list[str] = field(default_factory=list)
    hosts: list[dict] = field(default_factory=list)

    # ── Description ───────────────────────────────────────────────────────────
    name: str = ""
    description: str = ""

    # ── Status / State ────────────────────────────────────────────────────────
    status: int = 20
    state: str = "open"

    # ── Tags ──────────────────────────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)

    # ── Scoring ───────────────────────────────────────────────────────────────
    fine_score: int = 0

    # ── Timestamps ────────────────────────────────────────────────────────────
    start: str = ""
    end: str = ""
    created: str = ""
    modified_timestamp: str = ""

    # ── Assignment ────────────────────────────────────────────────────────────
    assigned_to: str = ""
    assigned_to_name: str = ""

    # ── MITRE / Intel ─────────────────────────────────────────────────────────
    objectives: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    # ── Users / Lateral movement ──────────────────────────────────────────────
    users: list[str] = field(default_factory=list)
    lm_host_ids: list[str] = field(default_factory=list)
    lm_hosts_capped: bool = False

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.incident_id
