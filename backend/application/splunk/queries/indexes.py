"""Splunk index query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.splunk_event_repo import splunk_event_repo
from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope, complete

_INDEX_LINKS = ("_reload", "alternate", "disable", "edit", "list")


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
        entries.append(build_splunk_entry(
            idx.name, complete(content, "indexes"),
            id_path=f"https://localhost:8089/services/data/indexes/{idx.name}",
            links=_INDEX_LINKS, fields=False,
        ))
    return build_splunk_envelope(entries, links={
        "create": "/services/data/indexes/_new", "_reload": "/services/data/indexes/_reload",
        "_acl": "/services/data/indexes/_acl", "_validate": "/services/data/indexes/_validate",
    })


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
    }
    entry = build_splunk_entry(
        idx.name, complete(content, "indexes"), collection="data/indexes", links=_INDEX_LINKS,
    )
    return build_splunk_envelope([entry], total=1)
