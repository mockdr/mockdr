"""Elastic Security page/per_page pagination utility.

Kibana APIs use 1-based page numbering with a configurable ``per_page`` size,
unlike the offset-based pagination used by CrowdStrike or cursor-based used
by SentinelOne.
"""
from __future__ import annotations


def paginate_kibana(
    items: list,
    page: int = 1,
    per_page: int = 20,
) -> tuple[list, int]:
    """Paginate items using Kibana's page/per_page pattern.

    Args:
        items:    Full list of items to paginate.
        page:     Page number (1-based).
        per_page: Maximum number of items per page.

    Returns:
        ``(page_items, total)`` tuple where *page_items* is the sliced
        subset and *total* is the full item count before slicing.
    """
    total = len(items)
    start = (max(page, 1) - 1) * per_page
    page_items = items[start: start + per_page]
    return page_items, total
