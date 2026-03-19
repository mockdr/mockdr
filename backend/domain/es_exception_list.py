"""Domain dataclass for Elastic Security exception list entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsExceptionList:
    """An Elastic Security exception list (container).

    Field names match the real Kibana Exception List API format.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    list_id: str
    name: str
    description: str = ""

    # ── Type / scope ──────────────────────────────────────────────────────────
    type: str = "detection"
    namespace_type: str = "single"

    # ── Classification ────────────────────────────────────────────────────────
    tags: list[str] = field(default_factory=list)
    os_types: list[str] = field(default_factory=list)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at: str = ""
    created_by: str = ""
    updated_at: str = ""
    updated_by: str = ""

    # ── Versioning ────────────────────────────────────────────────────────────
    version: int = 1
