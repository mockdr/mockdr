"""Domain dataclass for Elastic Security exception list item entities."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EsExceptionItem:
    """An item within an Elastic Security exception list.

    Field names match the real Kibana Exception List Items API format.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id: str
    item_id: str
    list_id: str
    name: str
    description: str = ""

    # ── Type / scope ──────────────────────────────────────────────────────────
    type: str = "simple"
    namespace_type: str = "single"

    # ── Entries ───────────────────────────────────────────────────────────────
    entries: list[dict] = field(default_factory=list)

    # ── Classification ────────────────────────────────────────────────────────
    os_types: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_at: str = ""
    created_by: str = ""
    updated_at: str = ""
    updated_by: str = ""
