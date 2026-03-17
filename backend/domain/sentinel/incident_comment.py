"""Domain dataclass for Microsoft Sentinel Incident Comment entity."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SentinelIncidentComment:
    """A Microsoft Sentinel incident comment record.

    Maps 1:1 to real Sentinel ``/incidents/{id}/comments`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    comment_id: str
    incident_id: str = ""
    message: str = ""

    # ── Author ────────────────────────────────────────────────────────────────
    author_name: str = "MockDR"
    author_email: str = ""

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_time_utc: str = ""

    # ── Versioning ────────────────────────────────────────────────────────────
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.comment_id
