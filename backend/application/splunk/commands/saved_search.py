"""Splunk saved search command handlers."""
from __future__ import annotations

from domain.splunk.saved_search import SavedSearch
from repository.splunk.saved_search_repo import saved_search_repo

from .search import create_search_job


def create_saved_search(name: str, search: str, **kwargs: object) -> SavedSearch:
    """Create a new saved search.

    Args:
        name:   Saved search name.
        search: SPL query string.
        **kwargs: Additional saved search fields.

    Returns:
        The created SavedSearch.
    """
    ss = SavedSearch(
        name=name,
        search=search,
        description=str(kwargs.get("description", "")),
        cron_schedule=str(kwargs.get("cron_schedule", "*/5 * * * *")),
        is_scheduled=bool(kwargs.get("is_scheduled", False)),
        dispatch_earliest_time=str(kwargs.get("dispatch.earliest_time", "-24h@h")),
        dispatch_latest_time=str(kwargs.get("dispatch.latest_time", "now")),
    )
    saved_search_repo.save(ss)
    return ss


def update_saved_search(name: str, **kwargs: object) -> SavedSearch | None:
    """Update an existing saved search.

    Args:
        name:    Saved search name.
        **kwargs: Fields to update.

    Returns:
        The updated SavedSearch, or None if not found.
    """
    ss = saved_search_repo.get(name)
    if not ss:
        return None

    allowed = {
        "search", "description", "cron_schedule", "is_scheduled",
        "disabled", "dispatch_earliest_time", "dispatch_latest_time",
        "alert_type", "alert_comparator", "alert_threshold", "actions",
    }
    for key, value in kwargs.items():
        clean_key = key.replace(".", "_").replace("-", "_")
        if clean_key in allowed:
            setattr(ss, clean_key, value)

    saved_search_repo.save(ss)
    return ss


def delete_saved_search(name: str) -> bool:
    """Delete a saved search.

    Args:
        name: Saved search name.

    Returns:
        True if found and deleted.
    """
    return saved_search_repo.delete(name)


def dispatch_saved_search(name: str) -> str | None:
    """Run a saved search and return the job SID.

    Args:
        name: Saved search name.

    Returns:
        The search job SID, or None if saved search not found.
    """
    ss = saved_search_repo.get(name)
    if not ss:
        return None

    sid = create_search_job(
        search=ss.search,
        earliest_time=ss.dispatch_earliest_time,
        latest_time=ss.dispatch_latest_time,
    )
    ss.history.insert(0, sid)
    saved_search_repo.save(ss)
    return sid
