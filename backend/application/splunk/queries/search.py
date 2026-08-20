"""Splunk search job query handlers (read-only)."""
from __future__ import annotations

from repository.splunk.search_job_repo import search_job_repo
from utils.splunk.response import (
    build_search_results,
    build_splunk_entry,
    build_splunk_envelope,
)


def _splunk_bool(value: bool) -> str:
    """Render a boolean the way splunkd does in Atom content: ``"1"``/``"0"``."""
    return "1" if value else "0"


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

    # splunkd renders every Atom content value as a string, booleans as "1"/"0"
    # — and splunklib depends on it: Job.is_done() is
    # `self._state.content["isDone"] == "1"`. Emitting a JSON bool made that
    # comparison permanently False, so the SDK's documented polling loop
    # (`while not job.is_done(): sleep(.2)`) never terminated against the mock.
    content = {
        "sid": job.sid,
        "dispatchState": job.dispatch_state,
        "doneProgress": str(job.done_progress),
        "eventCount": str(job.event_count),
        "resultCount": str(job.result_count),
        "scanCount": str(job.scan_count),
        "isDone": _splunk_bool(job.is_done),
        "isFailed": _splunk_bool(job.is_failed),
        "isPaused": _splunk_bool(job.is_paused),
        "isSaved": _splunk_bool(job.is_saved),
        "ttl": str(job.ttl),
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
            "doneProgress": str(job.done_progress),
            "eventCount": str(job.event_count),
            "resultCount": str(job.result_count),
            "isDone": _splunk_bool(job.is_done),
            "isFailed": _splunk_bool(job.is_failed),
        }
        entries.append(build_splunk_entry(job.sid, content))
    return build_splunk_envelope(entries)


def _page(rows: list[dict[str, object]], count: int, offset: int) -> list[dict[str, object]]:
    """Slice *rows*, treating ``count=0`` as "everything".

    Splunk documents zero as "return all available entries", and the SDK
    encodes it too (``Collection.null_count = 0``). Slicing by it returned an
    empty page, so the documented way to ask for a whole result set produced
    nothing.
    """
    windowed = rows[offset:]
    return windowed if count <= 0 else windowed[:count]


def get_results(sid: str, count: int = 100, offset: int = 0) -> dict | None:
    """Return search results for a job.

    Args:
        sid:    The search job SID.
        count:  Maximum number of results to return; ``0`` means all.
        offset: Starting offset.

    Returns:
        Search results envelope dict, or None if job not found.
    """
    job = search_job_repo.get(sid)
    if not job:
        return None

    return build_search_results(
        _page(job.results, count, offset),
        fields=job.field_list,
        init_offset=offset,
        messages=job.messages,
    )


def get_events(sid: str, count: int = 100, offset: int = 0) -> dict | None:
    """Return the events the search matched, before the pipeline reshaped them.

    Real Splunk's ``/events`` returns pre-transform events, so a transforming
    search makes eventCount and resultCount differ. This previously delegated
    straight to ``get_results``, so the two were always identical.
    """
    job = search_job_repo.get(sid)
    if not job:
        return None

    events = job.events or job.results
    fields = list(events[0].keys()) if events else []
    return build_search_results(
        _page(events, count, offset),
        fields=fields,
        init_offset=offset,
        messages=job.messages,
    )


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
