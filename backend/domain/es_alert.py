"""Domain dataclass for Elastic Security alert entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsAlert:
    """An Elastic Security alert (signal).

    Field names match the real Elastic Security alert document format.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str

    # ── Signal / workflow ─────────────────────────────────────────────────────
    signal_status: str = "open"
    signal_rule_id: str = ""
    signal_rule_name: str = ""
    signal_rule_severity: str = "medium"
    signal_rule_risk_score: int = 50

    # ── Agent / host ──────────────────────────────────────────────────────────
    agent_id: str = ""
    hostname: str = ""
    host_ip: str = ""
    host_os: str = ""

    # ── Process ───────────────────────────────────────────────────────────────
    process_name: str = ""
    process_executable: str = ""
    process_args: list[str] = field(default_factory=list)
    process_pid: int = 0

    # ── User ──────────────────────────────────────────────────────────────────
    user_name: str = ""

    # ── File ──────────────────────────────────────────────────────────────────
    file_name: str = ""
    file_path: str = ""
    file_hash_sha256: str = ""

    # ── Timestamp ─────────────────────────────────────────────────────────────
    timestamp: str = ""

    # ── MITRE ATT&CK ──────────────────────────────────────────────────────────
    threat_tactic_name: str = ""
    threat_tactic_id: str = ""
    threat_technique_name: str = ""
    threat_technique_id: str = ""

    # ── Metadata ──────────────────────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)
    assignees: list[dict] = field(default_factory=list)
    workflow_status: str = "open"
