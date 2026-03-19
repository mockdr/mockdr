"""Domain dataclass for Microsoft Sentinel Bookmark entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelBookmark:
    """A Microsoft Sentinel bookmark record.

    Maps 1:1 to real Sentinel ``/bookmarks`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    bookmark_id: str
    display_name: str = ""
    notes: str = ""

    # ── Query ─────────────────────────────────────────────────────────────────
    query: str = ""
    query_result: str = ""

    # ── Audit ─────────────────────────────────────────────────────────────────
    created: str = ""
    updated: str = ""
    created_by_object_id: str = ""
    created_by_name: str = "MockDR"

    # ── Relations ─────────────────────────────────────────────────────────────
    incident_id: str = ""
    labels: list[str] = field(default_factory=list)

    # ── Versioning ────────────────────────────────────────────────────────────
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.bookmark_id
