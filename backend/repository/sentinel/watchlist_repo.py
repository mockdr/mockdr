"""Repository for Microsoft Sentinel watchlist entities."""
from __future__ import annotations

from domain.sentinel.watchlist import SentinelWatchlist
from repository.base import Repository


class SentinelWatchlistRepository(Repository[SentinelWatchlist]):
    """In-memory repository for ``SentinelWatchlist`` domain objects."""

    def __init__(self) -> None:
        """Initialise the repository bound to the sentinel_watchlists collection."""
        super().__init__("sentinel_watchlists")



sentinel_watchlist_repo = SentinelWatchlistRepository()
