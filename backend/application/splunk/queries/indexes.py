"""Splunk index query handlers (read-only)."""
from __future__ import annotations

import json
from pathlib import Path

from repository.splunk.splunk_event_repo import splunk_event_repo
from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope, complete

_INDEX_LINKS = ("_reload", "alternate", "disable", "edit", "list")
#: The top-level relations the indexes collection offers, on the single-entry
#: answer as much as on the listing.
_INDEX_COLLECTION_LINKS = {
    "create": "/services/data/indexes/_new", "_reload": "/services/data/indexes/_reload",
    "_acl": "/services/data/indexes/_acl", "_validate": "/services/data/indexes/_validate",
}

#: splunkd reports an index as unmodifiable in place and writable by the
#: system role beside admin.
_INDEX_ACL = {"modifiable": False, "perms": {"read": ["*"], "write": ["admin",
                                                                     "splunk-system-role"]}}

#: The indexes an install brings with it. splunkd reports them as owned by
#: `system`, not removable, and offers no `remove` link for them; an index
#: created through the API is app-level and removable. mockdr reported every
#: index the same way, so a client could not tell `main` from one it had made
#: — and was offered a link to remove an index splunkd would refuse to remove.
_SYSTEM_INDEXES = frozenset({"main", "history", "summary", "splunklogger"})


def _is_system(name: str) -> bool:
    return name in _SYSTEM_INDEXES or name.startswith("_")


def _index_acl(name: str) -> dict:
    """The ACL splunkd reports for this index."""
    if _is_system(name):
        return {**_INDEX_ACL, "app": "system", "sharing": "system", "removable": False}
    return {**_INDEX_ACL, "app": "search", "sharing": "app", "removable": True}


def _index_links(name: str, *, created: bool = False) -> tuple[str, ...]:
    """The link relations splunkd offers for this index."""
    links = ("_reload", "alternate", "edit", "list") if created else _INDEX_LINKS
    return (*links, "remove") if not _is_system(name) else links


def _index_fields() -> dict:
    """The ``fields`` block splunkd reports for an index entry.

    80 optional names, recorded from 10.4.2. mockdr sent three empty lists,
    so a client reading which settings an index takes was told: none.
    """
    path = (Path(__file__).resolve().parents[3] / "infrastructure" / "fixtures"
            / "splunk" / "indexes_entry_fields.json")
    return dict(json.loads(path.read_text())["fields"])


def list_indexes() -> dict:
    """Return all indexes in Splunk envelope format."""
    indexes = splunk_index_repo.list_all()
    # Counted here rather than on ingest: a count kept up to date per event
    # made every write scan the event store, and this is the only place the
    # number is read.
    counts = splunk_event_repo.counts_by_index()
    entries = []
    for idx in indexes:
        content = {
            "totalEventCount": counts.get(idx.name, idx.total_event_count),
            "currentDBSizeMB": str(idx.current_db_size_mb),
            "maxDataSize": idx.max_data_size,
            "frozenTimePeriodInSecs": idx.frozen_time_period_in_secs,
            "disabled": idx.disabled,
            "datatype": idx.data_type,
            "minTime": idx.min_time,
            "maxTime": idx.max_time,
        }
        content = {**content, **idx.settings}
        entries.append(build_splunk_entry(
            idx.name, complete(content, "indexes"),
            collection="data/indexes",
            links=_index_links(idx.name), fields=False, acl_extra=_index_acl(idx.name),
        ))
    return build_splunk_envelope(entries, links=_INDEX_COLLECTION_LINKS)


def get_index(name: str) -> dict | None:
    """Return a single index in Splunk envelope format."""
    idx = splunk_index_repo.get(name)
    if not idx:
        return None
    content = {
        "totalEventCount": splunk_event_repo.count_by_index(idx.name) or idx.total_event_count,
        "currentDBSizeMB": str(idx.current_db_size_mb),
        "maxDataSize": idx.max_data_size,
        "frozenTimePeriodInSecs": idx.frozen_time_period_in_secs,
        "disabled": idx.disabled,
        "datatype": idx.data_type,
        # The three paths splunkd derives from the index name.
        "homePath": f"$SPLUNK_DB/{idx.name}/db",
        "coldPath": f"$SPLUNK_DB/{idx.name}/colddb",
        "thawedPath": f"$SPLUNK_DB/{idx.name}/thaweddb",
        **idx.settings,
    }
    entry = build_splunk_entry(
        idx.name, complete(content, "indexes"), collection="data/indexes",
        links=_index_links(idx.name), fields=_index_fields(),
        acl_extra=_index_acl(idx.name),
    )
    return build_splunk_envelope([entry], total=1, links=_INDEX_COLLECTION_LINKS)


def created_index(name: str) -> dict:
    """The answer to a create, which differs from a read in two ways.

    splunkd sends no ``fields`` block and no ``disable`` link for an index it
    has just made — the entry describes what was created, not what can now be
    done to it.
    """
    answer = get_index(name)
    if not answer:
        return {}
    entry = answer["entry"][0]
    entry.pop("fields", None)
    entry["links"] = {
        rel: path for rel, path in entry["links"].items() if rel != "disable"
    }
    return answer
