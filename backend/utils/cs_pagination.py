"""CrowdStrike offset/limit pagination utility.

CrowdStrike APIs use simple offset-based pagination rather than the
cursor-based pagination used by SentinelOne.
"""
from __future__ import annotations


def paginate_cs(
    items: list,
    offset: int = 0,
    limit: int = 100,
) -> tuple[list, int]:
    """Paginate items using CrowdStrike's offset/limit pattern.

    Args:
        items:  Full list of items to paginate.
        offset: Starting offset (zero-based index).
        limit:  Maximum number of items per page.

    Returns:
        ``(page, total)`` tuple where *page* is the sliced subset and
        *total* is the full item count before slicing.
    """
    total = len(items)
    page = items[offset: offset + limit]
    return page, total
