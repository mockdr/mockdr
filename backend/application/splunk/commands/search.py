"""Splunk search job command handlers (mutations)."""
from __future__ import annotations

import json
import re
import time
import uuid

from domain.splunk.search_job import SearchJob
from repository.splunk.notable_event_repo import notable_event_repo
from repository.splunk.search_job_repo import search_job_repo
from repository.splunk.splunk_event_repo import splunk_event_repo
from utils.splunk.spl_exec import (
    aggregation_aliases,
    execute_pipeline,
    expand_fields,
    split_by,
)
from utils.splunk.spl_parser import (
    SPLQuery,
    current_time,
    parse_spl,
    resolve_relative_time,
)

#: What splunkd says about a `latest_time` it will not take — the same line
#: whether the value is unreadable or merely not after `earliest_time`.
_LATEST_PARAM_MESSAGE = "Invalid latest_time: latest_time must be after earliest_time."


class UnknownSearchCommandError(ValueError):
    """Raised when the pipeline names a command splunkd does not have.

    It refuses the dispatch with 400 rather than running the stages it did
    recognise, which would answer with a result set the search never asked
    for.
    """

    def __init__(self, command: str) -> None:
        """Record the command name, for splunkd's own wording."""
        self.command = command
        super().__init__(f"Unknown search command '{command}'.")


class InvalidTimeParameterError(ValueError):
    """Raised when ``earliest_time``/``latest_time`` is not a time splunkd takes.

    It answers the request with 400 rather than dispatching a job; the mock
    used to drop the bound it could not read and search everything instead.
    """

    def __init__(self, message: str) -> None:
        """Record splunkd's own wording for the refusal."""
        super().__init__(message)


def _validate_time_parameters(earliest_time: str, latest_time: str) -> None:
    """Refuse the request the way splunkd refuses it.

    Raises:
        InvalidTimeParameterError: If either parameter cannot be read, or if
            both are given and ``latest_time`` is not strictly after
            ``earliest_time`` — splunkd rejects equal bounds here, though it
            accepts them when the same values are written into the search
            string (both measured against Splunk 9).
    """
    # One clock reading for both bounds, so `earliest_time=-5m
    # latest_time=-5m` is the equal pair splunkd refuses rather than a window
    # a few microseconds wide.
    now = current_time()
    earliest = resolve_relative_time(earliest_time, now) if earliest_time else None
    if earliest_time and not earliest:
        raise InvalidTimeParameterError("Invalid earliest_time.")
    latest = resolve_relative_time(latest_time, now) if latest_time else None
    if latest_time and not latest:
        raise InvalidTimeParameterError(_LATEST_PARAM_MESSAGE)
    if earliest and latest and latest <= earliest:
        raise InvalidTimeParameterError(_LATEST_PARAM_MESSAGE)


def create_search_job(
    search: str,
    earliest_time: str = "",
    latest_time: str = "",
    exec_mode: str = "normal",
    status_buckets: int = 0,
    request: dict[str, str] | None = None,
) -> str:
    """Create a search job, execute the SPL query, and store results.

    Args:
        search:         SPL query string.
        earliest_time:  Earliest time modifier.
        latest_time:    Latest time modifier.
        exec_mode:      Execution mode (normal, blocking, oneshot).
        status_buckets: Number of status buckets.
        request:        The dispatch arguments as the client sent them,
                        which the job echoes back unchanged.

    Returns:
        The search job SID.

    Raises:
        InvalidTimeParameterError: If ``earliest_time`` or ``latest_time`` is
            not a time splunkd can read. It refuses the request outright
            rather than dispatching a job with a bound it had to guess at.
    """
    sid = str(uuid.uuid4()).replace("-", "")[:24]
    sid = f"1{int(time.time())}.{sid}"

    now = time.time()
    parsed = parse_spl(search)
    # An explicit parameter overrides what the search string said, and is
    # validated here: splunkd answers 400 for the parameter and a FATAL
    # message inside a 200 for the same value written into the search.
    if parsed.unknown_command:
        raise UnknownSearchCommandError(parsed.unknown_command)
    _validate_time_parameters(earliest_time, latest_time)
    if earliest_time:
        parsed.earliest_time = earliest_time
        parsed.from_search_string = False
    if latest_time:
        parsed.latest_time = latest_time
        parsed.from_search_string = False

    events, results, messages = _execute_query(parsed)
    # splunkd marks a search that could not run FAILED; a client polling
    # dispatchState saw DONE here and concluded the empty result set was the
    # answer. The job entry repeats the FATAL line as an ERROR — the results
    # body does not, so that duplication lives in the job renderer.
    failed = any(m["type"] == "FATAL" for m in messages)

    job = SearchJob(
        sid=sid,
        search=search,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode=exec_mode,
        request=dict(request or {"search": search}),
        status_buckets=status_buckets,
        dispatch_state="FAILED" if failed else "DONE",
        is_failed=failed,
        done_progress=1.0,
        # eventCount counts what the search matched; resultCount counts what
        # the pipeline produced. A transforming search makes them differ.
        event_count=len(events),
        result_count=len(results),
        scan_count=len(events),
        results=results,
        events=events,
        messages=messages,
        field_list=list(results[0].keys()) if results else [],
        field_meta=describe_fields(parsed, results),
        is_done=True,
        published_at=now,
        touched_at=now,
    )
    search_job_repo.save(job)
    return sid


#: What splunkd says it did, per action. Every one of them used to answer
#: the same generic line, so a client reading the message could not tell a
#: pause from a finalize — and `save` and `setttl` name the ttl they set.
CONTROL_MESSAGES = {
    "cancel": "Search job cancelled.",
    "pause": "Search job paused.",
    "unpause": "Search job continued.",
    "finalize": "Search job finalized.",
    "touch": "Search job touched.",
    "enablepreview": "Search job results preview enabled.",
    "disablepreview": "Search job results preview disabled.",
}

#: What `save` sets the ttl to, measured on 10.4.2: a week.
SAVED_TTL = 604800


def control_message(action: str, ttl: int) -> str:
    """The sentence splunkd answers this action with."""
    if action in ("save", "setttl"):
        return f"The ttl of the search job was changed to {ttl}."
    return CONTROL_MESSAGES.get(action, "Search job touched.")


def apply_control_action(sid: str, action: str, ttl: int = 0) -> bool:
    """Apply a job control action, changing the job's observable state.

    Only ``cancel`` did anything; the rest were accepted and ignored, so a
    client could not tell a paused job from a running one or observe a
    finalize taking effect.

    Args:
        sid:    The search job SID.
        action: One of splunkd's job control actions.
        ttl:    The seconds `setttl` was asked for, where it applies.

    Returns:
        True if the job existed and the action was applied.
    """
    job = search_job_repo.get(sid)
    if not job:
        return False

    now = time.time()
    if action == "cancel":
        # splunkd *removes* a cancelled job: the sid stops resolving, and a
        # client waiting for it to disappear used to wait for ever because
        # this only marked it failed and kept it.
        search_job_repo.delete(sid)
        return True
    elif action == "pause":
        if not job.is_paused:
            job.paused_at = now
        job.is_paused = True
        # `PAUSE`, not `PAUSED` — measured twice on 10.4.2.
        job.dispatch_state = "PAUSE"
    elif action == "unpause":
        # Resume where the job stopped. Shifting the dispatch origin forward
        # by the paused duration is what keeps a paused job from silently
        # completing while it was held.
        if job.is_paused and job.paused_at:
            job.published_at += now - job.paused_at
        job.paused_at = 0.0
        job.is_paused = False
        job.dispatch_state = "DONE" if job.is_done else "RUNNING"
    elif action == "finalize":
        # Stop the search early: whatever it had, it now reports as final.
        job.dispatch_state = "DONE"
        job.is_done = True
        job.done_progress = 1.0
        job.settled = True
        job.is_finalized = True
    elif action == "save":
        job.is_saved = True
        job.ttl = SAVED_TTL
    elif action == "setttl":
        job.ttl = ttl
    elif action == "unsave":
        job.is_saved = False
    elif action == "touch":
        # Restarts the TTL countdown. It deliberately leaves published_at
        # alone: touching a job extends how long it is kept, it does not
        # re-dispatch the search.
        job.touched_at = now
    # setpriority and (dis|en)ablepreview are accepted and have no
    # observable effect on a mock that completes searches synchronously.
    search_job_repo.save(job)
    return True


def delete_search_job(sid: str) -> bool:
    """Delete a search job.

    Args:
        sid: The search job SID.

    Returns:
        True if the job existed and was deleted.
    """
    return search_job_repo.delete(sid)


#: Commands that produce their own rows rather than reading events. A search
#: that starts with one matches nothing, however many events the index holds.
_GENERATING_COMMANDS = frozenset({"makeresults"})


def _generates_its_own_rows(parsed: SPLQuery) -> bool:
    """Whether the search begins with a generating command."""
    first = parsed.commands[0].name if parsed.commands else ""
    return first in _GENERATING_COMMANDS and parsed.search_expr is None


def _execute_query(parsed: SPLQuery) -> tuple[list[dict], list[dict], list[dict]]:
    """Execute a parsed SPL query against the event store.

    Args:
        parsed: The parsed SPL query.

    Returns:
        ``(events, results, messages)`` — the matched events before the
        pipeline ran, the rows the pipeline produced, and any diagnostics.
    """
    time_messages, usable = _time_term_messages(parsed)
    if not usable:
        # splunkd refuses the whole search rather than dropping the bound it
        # could not read: a typo in `earliest` returned every event here and
        # none in production, which is the worst way for the two to differ.
        return [], [], time_messages

    if _generates_its_own_rows(parsed):
        # A generating search reads no index at all: `| makeresults` and the
        # rest make their rows out of nothing, so the job matched no events.
        # Handing it the whole event store made `/events` answer with
        # documents the search never touched.
        events = []
    elif parsed.is_notable or parsed.index == "notable":
        # The notable store *and* whatever was ingested into that index.
        # Serving only the store meant an event accepted by the receiver
        # with `?index=notable`, and reported under that index by
        # `stats count by index`, was invisible to `search index=notable` —
        # the mock disagreeing with itself about where it had just put
        # something.
        events = _query_notables(parsed) + _query_events(parsed)
    else:
        events = _query_events(parsed)

    results, pipeline_messages = execute_pipeline(events, parsed)
    messages = time_messages + pipeline_messages
    if any(m["type"] == "FATAL" for m in pipeline_messages):
        # A search that could not run reports no events either, the way a
        # failed dispatch does.
        return [], [], messages
    return events, results, messages


#: The columns `top` and `rare` generate, and what splunkd calls each.
_TOP_SPECIALS = {"count": "count", "percent": "percent"}


#: The commands that build a row rather than passing one along. After one of
#: these the column order is theirs; without one it is alphabetical.
_ORDERING_COMMANDS = frozenset({
    "table", "fields", "stats", "timechart", "top", "rare",
})


def describe_fields(parsed: SPLQuery, results: list[dict]) -> list[dict]:
    """Describe the result columns the way splunkd's `fields` block does.

    A group-by column carries its rank, so a client knows which columns it
    was grouped on and in what order; one an `eval` produced carries the type
    that eval gave it; and `top` marks the count and percentage it generated.
    A bare list of names told a renderer none of that.
    """
    if not results:
        return []
    last_command = parsed.commands[-1] if parsed.commands else None
    last = last_command.name if last_command else ""
    if last_command is not None and last == "table":
        # `table` declares its columns, so splunkd lists every name it was
        # given — including one no row turned out to carry.
        names = expand_fields(
            [f.strip() for f in re.split(r"[,\s]+", last_command.arg) if f.strip()],
            results,
        )
    else:
        # Every column any row carries, not only the ones the first row does:
        # `streamstats current=f sum(n)` leaves the first row without it.
        names = list(dict.fromkeys(k for row in results for k in row))
        names.extend(_declared_columns(parsed, names))
        if not any(c.name in _ORDERING_COMMANDS for c in parsed.commands):
            # Nothing in the pipeline built the row, so splunkd lists the
            # columns by name: `eval z=1, a=2` reads a before z, and so does
            # a plain search. Only a command that constructs the row fixes
            # the order it is written in.
            names = sorted(names)
    by_fields = _last_group_by(parsed)
    created = set(parsed.evals)

    described: list[dict] = []
    for name in names:
        entry: dict = {"name": name}
        if name in by_fields:
            entry["groupby_rank"] = str(by_fields.index(name))
            if name in created:
                # From a row that carries it, not from the first row: `names`
                # is the union across every row, and indexing the first with
                # a name only a later row has raised KeyError out of a
                # function every search runs.
                sample = next(
                    (r[name] for r in results if name in r), "")
                entry["type"] = "str" if isinstance(sample, str) else "num"
        if last in ("top", "rare") and name in _TOP_SPECIALS:
            entry["type_special"] = _TOP_SPECIALS[name]
        described.append(entry)
    return described


def _declared_columns(parsed: SPLQuery, present: list[str]) -> list[str]:
    """Columns ``stats`` named that no row ended up with.

    `stats sum(text_field) by host` lists `sum(text_field)` and writes it in
    no row. `streamstats` does not do this — a column it could not compute
    for any row is absent from the block as well (both measured).
    """
    for command in reversed(parsed.commands):
        if command.name == "stats":
            return [
                alias for alias in aggregation_aliases(command.arg)
                if alias not in present
            ]
    return []


def _last_group_by(parsed: SPLQuery) -> list[str]:
    """The by-fields of the last grouping command, in the order given."""
    for command in reversed(parsed.commands):
        if command.name in ("stats", "timechart"):
            _, by_fields = split_by(command.arg)
            return ["_time"] if command.name == "timechart" and not by_fields else by_fields
    return []


def _time_term_messages(parsed: SPLQuery) -> tuple[list[dict], bool]:
    """Diagnose the search's time terms the way splunkd reports them.

    Returns:
        The messages to attach, and whether the search can run at all. An
        unreadable ``earliest`` or ``latest`` is FATAL and yields no results;
        a readable one that came from the search string is announced with the
        INFO line splunkd emits (both measured against Splunk 9).
    """
    bounds: dict[str, float] = {}
    now = current_time()
    for term in ("earliest", "latest"):
        value = getattr(parsed, f"{term}_time")
        if not value:
            continue
        resolved = resolve_relative_time(value, now)
        if not resolved:
            # Only the first bad term is reported, as splunkd does.
            return (
                [{"type": "FATAL", "text": f'Invalid value "{value}" for time term \'{term}\''}],
                False,
            )
        bounds[term] = resolved

    start, end = bounds.get("earliest"), bounds.get("latest")
    if start and end and start > end:
        # An inverted window is a parse failure in the search itself, and
        # splunkd quotes the two epochs it resolved them to.
        return ([{
            "type": "FATAL",
            "text": (
                "Error in 'search' command: Unable to parse the search: "
                f"Invalid time bounds in search: start={int(start)} > end={int(end)}."
            ),
        }], False)

    if parsed.from_search_string and (parsed.earliest_time or parsed.latest_time):
        return ([{
            "type": "INFO",
            "text": "Your timerange was substituted based on your search string",
        }], True)
    return ([], True)


def _query_events(parsed: SPLQuery) -> list[dict]:
    """Query events from the event store."""
    all_events = splunk_event_repo.list_all()

    # Time filtering
    now = current_time()
    earliest = resolve_relative_time(parsed.earliest_time, now) if parsed.earliest_time else 0.0
    latest = resolve_relative_time(parsed.latest_time, now) if parsed.latest_time else 0.0

    filtered = []
    for event in all_events:
        if parsed.index and event.index != parsed.index:
            continue
        if parsed.sourcetype and event.sourcetype != parsed.sourcetype:
            continue
        if parsed.source and event.source != parsed.source:
            continue
        if parsed.host and event.host != parsed.host:
            continue
        if earliest and event.time < earliest:
            continue
        if latest and event.time > latest:
            continue

        # Build result dict from event
        result: dict[str, object] = {
            "_time": str(event.time),
            "index": event.index,
            "sourcetype": event.sourcetype,
            "source": event.source,
            "host": event.host,
            "_raw": event.raw,
        }
        # Merge extracted fields
        result.update(event.fields)
        filtered.append(result)

    # Sort by time descending by default
    filtered.sort(key=lambda r: float(str(r.get("_time", 0) or 0)), reverse=True)
    return filtered


def _query_notables(parsed: SPLQuery) -> list[dict]:
    """Query notable events for the notable macro."""
    notables = notable_event_repo.list_all()

    results = []
    for n in notables:
        result: dict[str, object] = {
            "event_id": n.event_id,
            "rule_name": n.rule_name,
            "rule_title": n.rule_title,
            "rule_id": n.rule_id,
            "search_name": n.search_name,
            "security_domain": n.security_domain,
            "severity": n.severity,
            "urgency": n.urgency,
            "status": n.status,
            "status_label": n.status_label,
            "owner": n.owner,
            "src": n.src,
            "dest": n.dest,
            "user": n.user,
            "description": n.description,
            "drilldown_search": n.drilldown_search,
            "time": n.time,
            "_time": n._time,
            "info_min_time": n.info_min_time,
            "info_max_time": n.info_max_time,
            "sourcetype": "stash",
            "index": "notable",
            "_raw": json.dumps({
                "event_id": n.event_id,
                "rule_name": n.rule_name,
                "severity": n.severity,
                "description": n.description,
            }),
        }
        results.append(result)

    # Sort by time descending
    results.sort(key=lambda r: float(str(r.get("_time", 0) or 0)), reverse=True)
    return results
