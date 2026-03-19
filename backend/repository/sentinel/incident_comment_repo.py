"""Repository for Microsoft Sentinel incident comment entities."""
from __future__ import annotations

from domain.sentinel.incident_comment import SentinelIncidentComment
from repository.base import Repository


class SentinelIncidentCommentRepository(Repository[SentinelIncidentComment]):
    """In-memory repository for ``SentinelIncidentComment`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_incident_comments collection."""
        super().__init__("sentinel_incident_comments")

    def get_by_incident_id(self, incident_id: str) -> list[SentinelIncidentComment]:
        """Return all comments for the given incident."""
        return [c for c in self.list_all() if c.incident_id == incident_id]



sentinel_incident_comment_repo = SentinelIncidentCommentRepository()
