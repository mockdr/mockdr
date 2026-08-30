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
    complete,
    fixture_links,
)
from utils.splunk.spl_exec import SPLUNK_SERVER

#: A job's links are its sub-resources, not edit/remove; its ACL has a ttl (a string)
#: and no can_list/removable; and neither a job nor the job list carries a
#: fields block or top-level links. All measured on 10.4.2.
_JOB_LINKS = fixture_links("search_jobs")


def _retime(content: dict, job: SearchJob) -> dict:
    """Anchor the fixture's search telemetry on this job's own start time.

    The captured ``searchTelemetry.search_commands[*].span`` values are epoch
    seconds from the capture run; shifted so the earliest span starts when
    this job was dispatched, with their relative offsets kept. Whole seconds
    are emitted as integers, as splunkd serialises them.
    """
    telemetry = content.get("searchTelemetry")
    if not isinstance(telemetry, dict):
        return content
    commands = telemetry.get("search_commands")
    if not isinstance(commands, list) or not commands:
        return content
    starts = [c["span"]["start"] for c in commands if isinstance(c.get("span"), dict)]
    if not starts:
        return content
    shift = (job.published_at or time.time()) - min(starts)
    content = {**content, "searchTelemetry": {**telemetry, "search_commands": []}}
    for cmd in commands:
        span = cmd.get("span")
        if isinstance(span, dict):
            span = {
                k: _whole(round(v + shift, 3)) if isinstance(v, (int, float)) else v
                for k, v in span.items()
            }
            cmd = {**cmd, "span": span}
        content["searchTelemetry"]["search_commands"].append(cmd)
    return content


def _iso(epoch: float) -> str:
    """A job's ``published`` timestamp, in splunkd's ``+00:00`` form."""
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(epoch or time.time()))


_JOB_ACL = {
    "app": "search",
    "can_write": True,
    "modifiable": True,
    "owner": "admin",
    "perms": {"read": ["*"], "write": ["*"]},
    "sharing": "global",
    "ttl": "600",
}

#: The states a real search job passes through, as fractions of the dispatch
#: window. A job reports the last state whose threshold it has passed.
_DISPATCH_STATES: tuple[tuple[float, str], ...] = (
    (0.00, "QUEUED"),
    (0.20, "PARSING"),
    (0.40, "RUNNING"),
    (0.80, "FINALIZING"),
    (1.00, "DONE"),
)


#: What splunkd does *not* send while a job is still parsing.  It carries 36
#: members then and 65 the moment it reaches RUNNING, 69 when done — so these
#: 34 appear together, at that one transition.  A client polling in the loop
#: the SDK documents reads its first answer here, and `eventCount` is exactly
#: what it reaches for; mockdr sent 31 of them from the first poll, so the
#: loop read a count that a real job has not got yet.  Measured on 10.4.2,
#: state by state.  QUEUED is treated the same way: it comes before PARSING
#: and cannot carry more, though it is too brief to catch and say so.
_ONLY_ONCE_RUNNING: frozenset[str] = frozenset({
    "canSummarize", "dropCount", "eventAvailableCount", "eventCount",
    "eventFieldCount", "eventIsStreaming", "eventIsTruncated", "eventSearch",
    "eventSorting", "fieldMetadataEvents", "fieldMetadataResults",
    "fieldMetadataStatic", "indexEarliestTime", "indexLatestTime",
    "isBatchModeSearch", "isRealTimeSearch", "isRemoteTimeline",
    "isTimeCursored", "is_prjob", "keywords", "normalizedSearch",
    "optimizedSearch", "phase0", "phase1", "remoteSearch", "reportSearch",
    "resultCount", "resultIsStreaming", "runDuration", "scanCount",
    "searchCanBeEventType", "searchTelemetry", "searchTotalBucketsCount",
    "searchTotalEliminatedBucketsCount",
})

#: The states that carry the shorter document.
_BEFORE_RUNNING = frozenset({"QUEUED", "PARSING"})


def _while_parsing(content: dict, state: str) -> dict:
    """Drop what splunkd has not worked out yet."""
    if state not in _BEFORE_RUNNING:
        return content
    return {k: v for k, v in content.items() if k not in _ONLY_ONCE_RUNNING}


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
        return job.dispatch_state, _whole(job.done_progress), job.is_done
    if SPLUNK_DISPATCH_SECONDS <= 0 or job.exec_mode == "blocking":
        return job.dispatch_state, _whole(job.done_progress), job.is_done

    # A paused job's clock stops, so it keeps reporting the progress it had
    # reached rather than quietly completing while it was held.
    now = job.paused_at if job.is_paused and job.paused_at else time.time()
    elapsed = now - (job.published_at or 0.0)
    fraction = min(max(elapsed / SPLUNK_DISPATCH_SECONDS, 0.0), 1.0)
    if job.is_paused:
        # `PAUSE`, not the `PAUSED` one would guess: measured twice on
        # 10.4.2, and `unpause` puts it back to RUNNING.
        return "PAUSE", round(fraction, 3), False
    state = next(name for threshold, name in reversed(_DISPATCH_STATES) if fraction >= threshold)
    return state, _whole(round(fraction, 3)), state == "DONE"


def _whole(progress: float) -> int | float:
    """Splunkd reports a finished job's progress as the integer 1 (measured)."""
    return int(progress) if progress == int(progress) else progress


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

    # Native JSON types. 2.0.1 stringified every value here — "1"/"0" for
    # booleans — reasoning from splunklib's `content["isDone"] == "1"`. That
    # comparison is right for the Atom XML splunklib actually requests, where
    # everything is text; measured on Splunk 10.4.2, output_mode=json carries
    # real booleans and integers, on the job list and the single job alike.
    # The XML renderer stringifies on its own.
    state, progress, done = _progress(job)
    content = {
        "sid": job.sid,
        # What this job is, not what the recorded fixture was: these came
        # from `search_jobs.json` alone, so every job reported the query that
        # fixture had been recorded from — a client polling a job it had just
        # dispatched read back somebody else's search.
        **_search_members(job),
        "dispatchState": state,
        "doneProgress": progress,
        "eventCount": job.event_count,
        "resultCount": job.result_count,
        "scanCount": job.scan_count,
        "isDone": done,
        "isFailed": job.is_failed,
        # A job that ran to the end reports `false` here; only `finalize`
        # sets it, and a client reading it asks whether the results it has
        # are the whole answer.  The fixture said `false` for every job.
        "isFinalized": job.is_finalized,
        "isPaused": job.is_paused,
        "isSaved": job.is_saved,
        "ttl": job.ttl,
        # A failed job reports the reason twice: the FATAL the search raised
        # and an ERROR copy of it. Only the job entry carries the copy.
        "messages": job.messages + [
            {"type": "ERROR", "text": m["text"]}
            for m in job.messages if m["type"] == "FATAL"
        ],
    }
    # Every key a real job carries, and the eight sub-resource links a job
    # has instead of edit/remove (measured on 10.4.2).
    entry = build_splunk_entry(
        job.sid,
        _while_parsing(_retime(complete(content, "search_jobs"), job), state),
        collection="search/jobs",
        links=_JOB_LINKS,
        fields=False,
        acl=_JOB_ACL,
        published=_iso(job.published_at),
    )
    return build_splunk_envelope([entry], total=1, links={}, messages=False)


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
            **_search_members(job),
            "dispatchState": state,
            "doneProgress": progress,
            "eventCount": job.event_count,
            "resultCount": job.result_count,
            "isDone": done,
            "isFailed": job.is_failed,
        }
        entries.append(
            build_splunk_entry(
                job.sid,
                _retime(complete(content, "search_jobs"), job),
                collection="search/jobs",
                links=_JOB_LINKS,
                fields=False,
                acl=_JOB_ACL,
                published=_iso(job.published_at),
            )
        )
    return build_splunk_envelope(entries, links={}, messages=False)


def _page(rows: list[dict[str, object]], count: int, offset: int) -> list[dict[str, object]]:
    """Slice *rows*, treating ``count=0`` as "everything".

    Splunk documents zero as "return all available entries", and the SDK
    encodes it too (``Collection.null_count = 0``). Slicing by it returned an
    empty page, so the documented way to ask for a whole result set produced
    nothing.
    """
    windowed = rows[offset:]
    return windowed if count <= 0 else windowed[:count]


class SearchJobFailedError(LookupError):
    """Raised when a job's results are asked for but the search never ran.

    splunkd answers ``/results`` and ``/events`` for a failed job with 400 and
    the messages that explain why, not with an empty page — which is what the
    mock used to return, and reads as "the search ran and found nothing".
    """

    def __init__(self, messages: list[dict[str, str]]) -> None:
        """Carry the job's messages so the route can render them."""
        self.messages = messages
        super().__init__("search job failed")


def _refuse_if_failed(job: object) -> None:
    """Raise if *job* failed, so the caller answers 400 rather than a page."""
    if getattr(job, "is_failed", False):
        raise SearchJobFailedError(getattr(job, "messages", []))


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
    _refuse_if_failed(job)

    return build_search_results(
        _page(job.results, count, offset),
        fields=job.field_meta or job.field_list,
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
    _refuse_if_failed(job)

    # No fallback to the results: a generating search matched no events, and
    # answering with the rows it produced put documents in `/events` that the
    # search never touched.
    events = [
        _with_internal_fields(event, offset + n)
        for n, event in enumerate(_page(job.events, count, offset))
    ]
    fields = list(events[0].keys()) if events else []
    return build_search_results(
        events,
        fields=fields,
        init_offset=offset,
        messages=job.messages,
    )


def _search_members(job: SearchJob) -> dict[str, object]:
    """The members of a job's content that repeat its own search.

    splunkd renders the query several ways: `search` and `request.search`
    are the client's text verbatim, and `eventSearch`, `optimizedSearch`,
    `normalizedSearch` and `remoteSearch` are the planner's renderings of
    it. The renderings here are approximations — mockdr has no planner — but
    they name *this* job's query, which the fixture's did not.
    """
    text = job.search
    return {
        "search": text,
        "request": dict(job.request) or {"search": text},
        "eventSearch": text,
        "optimizedSearch": f"| {text}" if text else "",
        "normalizedSearch": text,
        "remoteSearch": text,
        "label": "",
    }


#: The instance a bucket belongs to. splunkd's `_bkt` names it, and a client
#: that reads a bucket id back apart needs the three parts to line up.
_BUCKET_GUID = "MOCKDR-SPLUNK-0000-0000-000000000001"
_BUCKET_ID = 1

#: What splunkd keeps with an event and returns from `/events`, beside the
#: internal members it stamps on: the raw text, when it happened, and where
#: it came from. Measured on 10.4.2.
_INDEXED_MEMBERS = frozenset({"_raw", "_time", "host", "index", "source", "sourcetype"})


def _with_internal_fields(event: dict, serial: int) -> dict:
    """Attach the members splunkd puts on every event it returns.

    `/events` served the indexed members alone: an event came back without
    `_bkt`, `_cd`, `_indextime`, `_serial`, `_si`, `_sourcetype`, `linecount`
    or `splunk_server` (measured on 10.4.2 against the same seeded event).
    A client that de-duplicates on `_cd`, orders on `_serial`, or locates the
    event's index through `_si` found none of them and had nothing to fall
    back on — every event looked identical to every other.

    They are strings, as splunkd sends them, and derived from the event so
    that reading one twice gives the same answer.

    What comes back beside them is the event as it was indexed — `_raw` and
    the members splunkd keeps with it. mockdr also returned the fields it had
    parsed *out* of `_raw`, which `/events` does not carry (measured on
    10.4.2 against the same seeded event): a client reading `/events` to see
    what was ingested saw mockdr's parse of it instead.
    """
    index = str(event.get("index") or "main")
    raw = str(event.get("_raw") or "")
    indexed = event.get("_indextime")
    if indexed is None:
        indexed = int(float(event.get("_time") or 0))
    return {
        "_bkt": f"{index}~{_BUCKET_ID}~{_BUCKET_GUID}",
        "_cd": f"{_BUCKET_ID}:{serial}",
        "_indextime": str(int(float(indexed))),
        "_serial": str(serial),
        "_si": [SPLUNK_SERVER, index],
        "_sourcetype": str(event.get("sourcetype") or ""),
        "linecount": str(raw.count("\n") + 1 if raw else 0),
        "splunk_server": SPLUNK_SERVER,
        **{k: v for k, v in event.items() if k in _INDEXED_MEMBERS},
    }


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
