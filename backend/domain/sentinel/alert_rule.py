"""Domain dataclass for Microsoft Sentinel Alert Rule entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelAlertRule:
    """A Microsoft Sentinel alert rule record.

    Maps 1:1 to real Sentinel ``/alertRules`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    rule_id: str
    display_name: str = ""
    description: str = ""

    # ── Kind / severity ───────────────────────────────────────────────────────
    kind: str = "Scheduled"
    # Scheduled / Fusion / MLBehaviorAnalytics / MicrosoftSecurityIncidentCreation / NRT
    enabled: bool = True
    severity: str = "Medium"

    # ── Query ─────────────────────────────────────────────────────────────────
    query: str = ""
    query_frequency: str = "PT5H"
    query_period: str = "PT5H"
    trigger_operator: str = "GreaterThan"
    trigger_threshold: int = 0

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    # ── Additional ────────────────────────────────────────────────────────────
    product_filter: str = ""
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.rule_id
