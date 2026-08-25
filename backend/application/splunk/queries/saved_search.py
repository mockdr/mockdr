"""Splunk saved search query handlers (read-only)."""

from __future__ import annotations

from repository.splunk.saved_search_repo import saved_search_repo
from utils.splunk.response import (
    build_splunk_entry,
    build_splunk_envelope,
    complete,
    fixture_links,
    fixture_top_links,
)

#: A saved search's ACL carries the four sharing capabilities (10.4.2).
_SAVED_ACL = {
    "can_change_perms": True,
    "can_share_app": True,
    "can_share_global": True,
    "can_share_user": False,
}


_SAVED_LINKS = fixture_links("saved_searches")


def list_saved_searches() -> dict:
    """Return all saved searches in Splunk envelope format."""
    searches = saved_search_repo.list_all()
    entries = []
    for ss in searches:
        content = {
            "search": ss.search,
            "description": ss.description,
            "cron_schedule": ss.cron_schedule,
            "is_scheduled": ss.is_scheduled,
            "disabled": ss.disabled,
            "dispatch.earliest_time": ss.dispatch_earliest_time,
            "dispatch.latest_time": ss.dispatch_latest_time,
            "alert_type": ss.alert_type,
            "alert_comparator": ss.alert_comparator,
            "alert_threshold": ss.alert_threshold,
            "actions": ss.actions,
        }
        entries.append(
            build_splunk_entry(
                ss.name,
                complete(content, "saved_searches"),
                acl_extra=_SAVED_ACL,
                links=_SAVED_LINKS,
                collection="saved/searches",
                fields=False,
            )
        )
    return build_splunk_envelope(entries, links=fixture_top_links("saved_searches"))


def get_saved_search(name: str) -> dict | None:
    """Return a single saved search in Splunk envelope format."""
    ss = saved_search_repo.get(name)
    if not ss:
        return None
    content = {
        "search": ss.search,
        "description": ss.description,
        "cron_schedule": ss.cron_schedule,
        "is_scheduled": ss.is_scheduled,
        "disabled": ss.disabled,
        "dispatch.earliest_time": ss.dispatch_earliest_time,
        "dispatch.latest_time": ss.dispatch_latest_time,
        "alert_type": ss.alert_type,
        "actions": ss.actions,
    }
    entry = build_splunk_entry(
        ss.name,
        complete(content, "saved_searches"),
        acl_extra=_SAVED_ACL,
        links=_SAVED_LINKS,
        collection="saved/searches",
    )
    return build_splunk_envelope([entry], total=1)


def get_dispatch_history(name: str) -> dict | None:
    """Return dispatch history for a saved search."""
    ss = saved_search_repo.get(name)
    if not ss:
        return None
    entries = []
    for sid in ss.history:
        entries.append(build_splunk_entry(sid, {"sid": sid}))
    return build_splunk_envelope(entries)
