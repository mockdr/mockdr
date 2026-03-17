"""Domain dataclass for Microsoft Sentinel Watchlist entity."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SentinelWatchlist:
    """A Microsoft Sentinel watchlist record.

    Maps 1:1 to real Sentinel ``/watchlists`` API fields.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    watchlist_alias: str
    display_name: str = ""
    description: str = ""

    # ── Metadata ──────────────────────────────────────────────────────────────
    provider: str = "Microsoft"
    source: str = "Local file"
    items_search_key: str = ""
    content_type: str = "text/csv"

    # ── Audit ─────────────────────────────────────────────────────────────────
    created: str = ""
    updated: str = ""
    created_by_name: str = "MockDR"
    etag: str = ""

    # ── Items ─────────────────────────────────────────────────────────────────
    items: list[dict[str, object]] = field(default_factory=list)

    @property
    def id(self) -> str:
        """Return the primary identifier expected by ``Repository[T]``."""
        return self.watchlist_alias
