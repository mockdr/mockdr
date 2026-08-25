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
    #: Both stay unset until something actually changes. Kibana serves them
    #: as null on a record that has never been updated, and mockdr stamped
    #: them at creation — so every record looked as though it had been edited
    #: the moment it was made.
    updated_at: str | None = None
    updated_by: dict | None = None

    # ── Versioning ────────────────────────────────────────────────────────────
    version: str = "WzEsMV0="
