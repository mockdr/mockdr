"""Domain dataclass for Microsoft Sentinel Incident entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelIncident:
    """A Microsoft Sentinel incident record.

    Maps 1:1 to real Sentinel ``/incidents`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    incident_id: str
    title: str
    description: str

    # ── Status / severity ─────────────────────────────────────────────────────
    severity: str = "High"  # High / Medium / Low / Informational
    status: str = "New"  # New / Active / Closed

    # ── Classification ────────────────────────────────────────────────────────
    classification: str = ""
    classification_reason: str = ""
    classification_comment: str = ""

    # ── Owner ─────────────────────────────────────────────────────────────────
    owner_object_id: str = ""
    owner_email: str = ""
    owner_assigned_to: str = ""
    owner_upn: str = ""
    owner_type: str = "Unknown"

    # ── Labels ────────────────────────────────────────────────────────────────
    labels: list[dict[str, str]] = field(default_factory=list)

    # ── Timestamps ────────────────────────────────────────────────────────────
    first_activity_time_utc: str = ""
    last_activity_time_utc: str = ""
    created_time_utc: str = ""
    last_modified_time_utc: str = ""

    # ── Numeric / URL / Provider ──────────────────────────────────────────────
    incident_number: int = 0
    incident_url: str = ""
    provider_name: str = ""
    provider_incident_id: str = ""

    # ── Related IDs ───────────────────────────────────────────────────────────
    alert_ids: list[str] = field(default_factory=list)
    entity_ids: list[str] = field(default_factory=list)
    bookmark_ids: list[str] = field(default_factory=list)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    # ── Additional ────────────────────────────────────────────────────────────
    alert_product_names: list[str] = field(default_factory=list)
    related_analytic_rule_ids: list[str] = field(default_factory=list)

    # ── Versioning ────────────────────────────────────────────────────────────
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.incident_id
