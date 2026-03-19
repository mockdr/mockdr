"""Domain dataclass for Elastic Security detection rule entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsRule:
    """An Elastic Security detection rule.

    Field names match the real Elastic Detection Engine API format.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    rule_id: str
    name: str
    description: str = ""

    # ── Detection logic ───────────────────────────────────────────────────────
    type: str = "query"
    query: str = ""
    language: str = "kuery"
    index: list[str] = field(default_factory=lambda: ["logs-*", "filebeat-*"])

    # ── Severity / Risk ───────────────────────────────────────────────────────
    severity: str = "medium"
    risk_score: int = 50
    enabled: bool = True

    # ── Classification ────────────────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)
    threat: list[dict] = field(default_factory=list)
    author: list[str] = field(default_factory=lambda: ["Elastic"])

    # ── Versioning ────────────────────────────────────────────────────────────
    version: int = 1

    # ── Scheduling ────────────────────────────────────────────────────────────
    interval: str = "5m"
    from_field: str = "now-6m"
    max_signals: int = 100

    # ── Tuning ────────────────────────────────────────────────────────────────
    false_positives: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    actions: list[dict] = field(default_factory=list)
    exceptions_list: list[dict] = field(default_factory=list)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at: str = ""
    created_by: str = ""
    updated_at: str = ""
    updated_by: str = ""
    immutable: bool = False
