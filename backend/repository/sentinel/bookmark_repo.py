"""Repository for Microsoft Sentinel bookmark entities."""
from __future__ import annotations

from domain.sentinel.bookmark import SentinelBookmark
from repository.base import Repository


class SentinelBookmarkRepository(Repository[SentinelBookmark]):
    """In-memory repository for ``SentinelBookmark`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_bookmarks collection."""
        super().__init__("sentinel_bookmarks")

    def get_by_incident_id(self, incident_id: str) -> list[SentinelBookmark]:
        """Return all bookmarks associated with the given incident."""
        return [b for b in self.list_all() if b.incident_id == incident_id]



sentinel_bookmark_repo = SentinelBookmarkRepository()
