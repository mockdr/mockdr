"""Domain dataclass for Elastic Security endpoint action response entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsActionResponse:
    """An Elastic Security endpoint action response.

    Tracks the result of an action (isolate, unisolate, etc.) issued
    against a managed endpoint.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    agent_id: str

    # ── Action ────────────────────────────────────────────────────────────────
    action: str = "isolate"
    status: str = "pending"

    # ── Timestamps ────────────────────────────────────────────────────────────
    started_at: str = ""
    completed_at: str | None = None

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_by: str = ""

    # ── Parameters ────────────────────────────────────────────────────────────
    parameters: dict = field(default_factory=dict)
