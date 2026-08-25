"""Domain dataclass for Elastic Security case entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsCase:
    """An Elastic Security case.

    Field names match the real Kibana Cases API format.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    title: str
    description: str = ""

    # ── Status / severity ─────────────────────────────────────────────────────
    status: str = "open"
    severity: str = "low"

    # ── Classification ────────────────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)
    connector: dict = field(default_factory=lambda: {
        "id": "none", "name": "none", "type": ".none", "fields": None,
    })
    settings: dict = field(default_factory=lambda: {"syncAlerts": True})
    owner: str = "securitySolution"
    assignees: list[dict] = field(default_factory=list)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at: str = ""
    created_by: dict = field(default_factory=dict)
    #: Both stay unset until something actually changes. Kibana serves them
    #: as null on a record that has never been updated, and mockdr stamped
    #: them at creation — so every record looked as though it had been edited
    #: the moment it was made.
    updated_at: str | None = None
    updated_by: dict | None = None
    closed_at: str | None = None
    closed_by: dict | None = None

    # ── Versioning ────────────────────────────────────────────────────────────
    version: str = "WzEsMV0="

    # ── Counts ────────────────────────────────────────────────────────────────
    total_comment: int = 0
    total_alerts: int = 0
    # The alerts this case was opened from. total_alerts used to be a bare
    # random number with nothing behind it, so it could not be verified
    # against anything and a case pointed at no alert at all.
    alert_ids: list[str] = field(default_factory=list)
