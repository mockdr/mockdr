"""Domain dataclass for Microsoft Sentinel Threat Intelligence Indicator entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelThreatIndicator:
    """A Microsoft Sentinel threat intelligence indicator record.

    Maps 1:1 to real Sentinel ``/threatIntelligence/main/indicators`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    name: str
    display_name: str = ""
    description: str = ""

    # ── Pattern ───────────────────────────────────────────────────────────────
    pattern: str = ""
    pattern_type: str = "ipv4-addr"
    # ipv4-addr / domain-name / url / file / email-addr

    # ── Source / confidence ───────────────────────────────────────────────────
    source: str = ""
    confidence: int = 0

    # ── Threat classification ─────────────────────────────────────────────────
    threat_types: list[str] = field(default_factory=list)
    kill_chain_phases: list[dict] = field(default_factory=list)
    labels: list[str] = field(default_factory=list)
    external_references: list[dict] = field(default_factory=list)

    # ── Timestamps ────────────────────────────────────────────────────────────
    valid_from: str = ""
    valid_until: str = ""
    created: str = ""
    last_updated: str = ""

    # ── Flags ─────────────────────────────────────────────────────────────────
    revoked: bool = False
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.name
