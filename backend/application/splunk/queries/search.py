"""Splunk search job query handlers (read-only)."""
from __future__ import annotations

import time

from config import SPLUNK_DISPATCH_SECONDS
from domain.splunk.search_job import SearchJob
from repository.splunk.search_job_repo import search_job_repo
from utils.splunk.response import (
    build_search_results,
    build_splunk_entry,
    build_splunk_envelope,
)


def _splunk_bool(value: bool) -> str:
    """Render a boolean the way splunkd does in Atom content: ``"1"``/``"0"``."""
    return "1" if value else "0"


#: The states a real search job passes through, as fractions of the dispatch
#: window. A job reports the last state whose threshold it has passed.
_DISPATCH_STATES: tuple[tuple[float, str], ...] = (
    (0.00, "QUEUED"),
    (0.20, "PARSING"),
    (0.40, "RUNNING"),
    (0.80, "FINALIZING"),
    (1.00, "DONE"),
)


def _progress(job: SearchJob) -> tuple[str, float, bool]:
    """Return the job's ``(dispatchState, doneProgress, isDone)`` right now.

    The search runs synchronously, so a job is always *able* to answer. With
    the default dispatch window of zero it reports DONE immediately, which
    keeps every response deterministic. When a window is configured the job
    walks the states real Splunk walks, so a client polling ``isDone`` in the
    loop the SDK documents is actually exercised rather than short-circuited.

    A job whose state a control action fixed — cancelled, finalized, paused —
    reports that state. Deriving it from the clock regardless would let the
    clock overwrite an explicit instruction: a finalized job would go back to
    reporting QUEUED, so ``finalize`` would appear to do nothing at all.
    """
    if job.settled or job.is_failed:
        return job.dispatch_state, job.done_progress, job.is_done
    if SPLUNK_DISPATCH_SECONDS <= 0 or job.exec_mode == "blocking":
        return job.dispatch_state, job.done_progress, job.is_done

    # A paused job's clock stops, so it keeps reporting the progress it had
    # reached rather than quietly completing while it was held.
    now = job.paused_at if job.is_paused and job.paused_at else time.time()
    elapsed = now - (job.published_at or 0.0)
    fraction = min(max(elapsed / SPLUNK_DISPATCH_SECONDS, 0.0), 1.0)
    if job.is_paused:
        return "PAUSED", round(fraction, 3), False
    state = next(
        name for threshold, name in reversed(_DISPATCH_STATES) if fraction >= threshold
    )
    return state, round(fraction, 3), state == "DONE"


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
    state, progress, done = _progress(job)
    content = {
        "sid": job.sid,
        "dispatchState": state,
        "doneProgress": str(progress),
        "eventCount": str(job.event_count),
        "resultCount": str(job.result_count),
        "scanCount": str(job.scan_count),
        "isDone": _splunk_bool(done),
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
        state, progress, done = _progress(job)
        content = {
            "sid": job.sid,
            "dispatchState": state,
            "doneProgress": str(progress),
            "eventCount": str(job.event_count),
            "resultCount": str(job.result_count),
            "isDone": _splunk_bool(done),
            "isFailed": _splunk_bool(job.is_failed),
        }
        entries.append(build_splunk_entry(job.sid, content, collection="search/jobs"))
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
