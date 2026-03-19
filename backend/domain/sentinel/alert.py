"""Domain dataclass for Microsoft Sentinel Alert entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelAlert:
    """A Microsoft Sentinel alert record.

    Maps 1:1 to real Sentinel ``/incidents/{id}/alerts`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    alert_id: str
    alert_display_name: str = ""
    description: str = ""

    # ── Status / severity ─────────────────────────────────────────────────────
    severity: str = "Medium"
    status: str = "New"
    confidence_level: str = ""

    # ── Product ───────────────────────────────────────────────────────────────
    product_name: str = ""
    product_component_name: str = ""
    provider_alert_id: str = ""
    alert_type: str = ""

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    # ── Timestamps ────────────────────────────────────────────────────────────
    time_generated: str = ""
    processing_end_time: str = ""
    start_time_utc: str = ""
    end_time_utc: str = ""

    # ── Related IDs ───────────────────────────────────────────────────────────
    entity_ids: list[str] = field(default_factory=list)
    incident_id: str = ""

    # ── Additional ────────────────────────────────────────────────────────────
    vendor_name: str = ""
    alert_link: str = ""
    resource_identifiers: list[dict] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.alert_id
