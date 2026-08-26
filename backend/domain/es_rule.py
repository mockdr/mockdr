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
    #: The author's version, which only ever changes because a client set it.
    #: Counting updates here made every edit look like a new authored version.
    version: int = 1

    #: Kibana's own modification counter: it goes up when a rule's parameters
    #: change, and not when the rule is merely enabled or disabled.
    revision: int = 0

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

    # ── Execution ─────────────────────────────────────────────────────────────
    #: What the rule's last run reported, or None for a rule that has never
    #: run. Kibana renders this as `execution_summary`, and only ever shows it
    #: for a rule the task manager has actually executed.
    last_execution: dict | None = None

    #: Members Kibana echoes only when the client set them. Emitting them
    #: unconditionally told a client the rule had a `note` or a
    #: `timeline_title` when the product would not have mentioned either.
    optional_members: dict = field(default_factory=dict)
