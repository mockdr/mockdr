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
    updated_at: str = ""
    updated_by: dict = field(default_factory=dict)
    closed_at: str | None = None
    closed_by: dict | None = None

    # ── Versioning ────────────────────────────────────────────────────────────
    version: str = "WzEsMV0="

    # ── Counts ────────────────────────────────────────────────────────────────
    total_comment: int = 0
    total_alerts: int = 0
