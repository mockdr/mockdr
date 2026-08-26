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
    # Who made the comment: the caller, not a constant. An app-only token has
    # no signed-in user, so Sentinel's `ClientInfo` carries the application's
    # own name and object id and leaves the two user fields empty.
    author_name: str = ""
    author_email: str = ""
    author_object_id: str = ""

    # ── Audit ─────────────────────────────────────────────────────────────────
    created_time_utc: str = ""
    #: `IncidentCommentProperties.lastModifiedTimeUtc` is a `date-time` the
    #: service fills in. It was answered as an empty string, and an update
    #: left both timestamps as they were — so a client re-reading a comment
    #: saw new text under the old times.
    last_modified_time_utc: str = ""

    # ── Versioning ────────────────────────────────────────────────────────────
    etag: str = ""

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.comment_id
