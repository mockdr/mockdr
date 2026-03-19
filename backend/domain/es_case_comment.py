"""Domain dataclass for Elastic Security case comment entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsCaseComment:
    """A comment on an Elastic Security case.

    Field names match the real Kibana Cases comments API format.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    case_id: str

    # ── Content ───────────────────────────────────────────────────────────────
    comment: str = ""
    type: str = "user"

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at: str = ""
    created_by: dict = field(default_factory=dict)
    updated_at: str = ""
    updated_by: dict = field(default_factory=dict)

    # ── Versioning ────────────────────────────────────────────────────────────
    version: str = "WzEsMV0="
