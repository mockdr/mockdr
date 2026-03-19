"""Splunk search job query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.search_job_repo import search_job_repo
from utils.splunk.response import (
    build_search_results,
    build_splunk_entry,
    build_splunk_envelope,
)


def get_job(sid: str) -> dict | None:
    """Return a single search job in Splunk envelope format.

    Args:
        sid: The search job SID.

    Returns:
        Splunk envelope dict, or None if not found.
    """
    job = search_job_repo.get(sid)
    if not job:
        return None

    content = {
        "sid": job.sid,
        "dispatchState": job.dispatch_state,
        "doneProgress": job.done_progress,
        "eventCount": job.event_count,
        "resultCount": job.result_count,
        "scanCount": job.scan_count,
        "isDone": job.is_done,
        "isFailed": job.is_failed,
        "isPaused": job.is_paused,
        "isSaved": job.is_saved,
        "ttl": job.ttl,
    }
    entry = build_splunk_entry(
        job.sid,
        content,
        id_path=f"https://localhost:8089/services/search/jobs/{job.sid}",
    )
    return build_splunk_envelope([entry], total=1)


def list_jobs() -> dict:
    """Return all search jobs in Splunk envelope format.

    Returns:
        Splunk envelope dict with all jobs.
    """
    jobs = search_job_repo.list_all()
    entries = []
    for job in jobs:
        content = {
            "sid": job.sid,
            "dispatchState": job.dispatch_state,
            "doneProgress": job.done_progress,
            "eventCount": job.event_count,
            "resultCount": job.result_count,
            "isDone": job.is_done,
            "isFailed": job.is_failed,
        }
        entries.append(build_splunk_entry(job.sid, content))
    return build_splunk_envelope(entries)


def get_results(sid: str, count: int = 100, offset: int = 0) -> dict | None:
    """Return search results for a job.

    Args:
        sid:    The search job SID.
        count:  Maximum number of results to return.
        offset: Starting offset.

    Returns:
        Search results envelope dict, or None if job not found.
    """
    job = search_job_repo.get(sid)
    if not job:
        return None

    page = job.results[offset:offset + count]
    return build_search_results(
        page,
        fields=job.field_list,
        init_offset=offset,
    )


def get_events(sid: str, count: int = 100, offset: int = 0) -> dict | None:
    """Return raw events for a job (same as results for mock)."""
    return get_results(sid, count, offset)


def get_summary(sid: str) -> dict | None:
    """Return field summary for a job.

    Args:
        sid: The search job SID.

    Returns:
        Field summary dict, or None if job not found.
    """
    job = search_job_repo.get(sid)
    if not job:
        return None

    # Build basic field summary
    fields: dict[str, dict] = {}
    for field_name in job.field_list:
        fields[field_name] = {
            "count": str(len(job.results)),
            "distinct_count": str(len({str(r.get(field_name, "")) for r in job.results})),
            "is_exact": "1",
            "modes": [],
        }

    return {"fields": fields}


def get_timeline(sid: str) -> dict | None:
    """Return timeline data for a job.

    Args:
        sid: The search job SID.

    Returns:
        Timeline dict, or None if job not found.
    """
    job = search_job_repo.get(sid)
    if not job:
        return None

    return {
        "buckets": [],
        "event_count": job.event_count,
        "cursor_time": "",
    }
