"""Splunk index query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.response import build_splunk_entry, build_splunk_envelope


def list_indexes() -> dict:
    """Return all indexes in Splunk envelope format."""
    indexes = splunk_index_repo.list_all()
    entries = []
    for idx in indexes:
        content = {
            "totalEventCount": str(idx.total_event_count),
            "currentDBSizeMB": str(idx.current_db_size_mb),
            "maxDataSize": idx.max_data_size,
            "frozenTimePeriodInSecs": str(idx.frozen_time_period_in_secs),
            "disabled": idx.disabled,
            "datatype": idx.data_type,
            "minTime": idx.min_time,
            "maxTime": idx.max_time,
        }
        entries.append(build_splunk_entry(
            idx.name, content,
            id_path=f"https://localhost:8089/services/data/indexes/{idx.name}",
        ))
    return build_splunk_envelope(entries)


def get_index(name: str) -> dict | None:
    """Return a single index in Splunk envelope format."""
    idx = splunk_index_repo.get(name)
    if not idx:
        return None
    content = {
        "totalEventCount": str(idx.total_event_count),
        "currentDBSizeMB": str(idx.current_db_size_mb),
        "maxDataSize": idx.max_data_size,
        "frozenTimePeriodInSecs": str(idx.frozen_time_period_in_secs),
        "disabled": idx.disabled,
        "datatype": idx.data_type,
    }
    entry = build_splunk_entry(idx.name, content)
    return build_splunk_envelope([entry], total=1)
