"""Splunk search job command handlers (mutations)."""
from __future__ import annotations

import json
import time
import uuid

from domain.splunk.search_job import SearchJob
from repository.splunk.notable_event_repo import notable_event_repo
from repository.splunk.search_job_repo import search_job_repo
from repository.splunk.splunk_event_repo import splunk_event_repo
from utils.splunk.spl_exec import execute_pipeline
from utils.splunk.spl_parser import SPLQuery, parse_spl, resolve_relative_time


def create_search_job(
    search: str,
    earliest_time: str = "",
    latest_time: str = "",
    exec_mode: str = "normal",
    status_buckets: int = 0,
) -> str:
    """Create a search job, execute the SPL query, and store results.

    Args:
        search:         SPL query string.
        earliest_time:  Earliest time modifier.
        latest_time:    Latest time modifier.
        exec_mode:      Execution mode (normal, blocking, oneshot).
        status_buckets: Number of status buckets.

    Returns:
        The search job SID.
    """
    sid = str(uuid.uuid4()).replace("-", "")[:24]
    sid = f"1{int(time.time())}.{sid}"

    parsed = parse_spl(search)
    # Override time from explicit params if provided
    if earliest_time:
        parsed.earliest_time = earliest_time
    if latest_time:
        parsed.latest_time = latest_time

    events, results, messages = _execute_query(parsed)

    job = SearchJob(
        sid=sid,
        search=search,
        earliest_time=earliest_time,
        latest_time=latest_time,
        exec_mode=exec_mode,
        status_buckets=status_buckets,
        dispatch_state="DONE",
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
        is_done=True,
        published_at=time.time(),
    )
    search_job_repo.save(job)
    return sid


def cancel_search_job(sid: str) -> bool:
    """Cancel a running search job.

    Args:
        sid: The search job SID.

    Returns:
        True if the job was found and cancelled.
    """
    job = search_job_repo.get(sid)
    if not job:
        return False
    job.dispatch_state = "FAILED"
    job.is_done = True
    job.is_failed = True
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


def _execute_query(parsed: SPLQuery) -> tuple[list[dict], list[dict], list[dict]]:
    """Execute a parsed SPL query against the event store.

    Args:
        parsed: The parsed SPL query.

    Returns:
        ``(events, results, messages)`` — the matched events before the
        pipeline ran, the rows the pipeline produced, and any diagnostics.
    """
    if parsed.is_notable or parsed.index == "notable":
        events = _query_notables(parsed)
    else:
        events = _query_events(parsed)

    results, texts = execute_pipeline(events, parsed)
    messages = [{"type": "WARN", "text": text} for text in texts]
    return events, results, messages


def _query_events(parsed: SPLQuery) -> list[dict]:
    """Query events from the event store."""
    all_events = splunk_event_repo.list_all()

    # Time filtering
    earliest = resolve_relative_time(parsed.earliest_time) if parsed.earliest_time else 0.0
    latest = resolve_relative_time(parsed.latest_time) if parsed.latest_time else 0.0

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


def _apply_stats(results: list[dict], count_by: str) -> list[dict]:
    """Apply stats count by field aggregation."""
    counts: dict[str, int] = {}
    for r in results:
        key = str(r.get(count_by, ""))
        counts[key] = counts.get(key, 0) + 1
    return [{count_by: k, "count": v} for k, v in counts.items()]


def _apply_sort(results: list[dict], field_name: str, descending: bool) -> list[dict]:
    """Sort results by field."""
    return sorted(results, key=lambda r: str(r.get(field_name, "")), reverse=descending)


def _apply_renames(results: list[dict], renames: dict[str, str]) -> list[dict]:
    """Rename fields in results."""
    for r in results:
        for old, new in renames.items():
            if old in r:
                r[new] = r.pop(old)
    return results


def _apply_evals(results: list[dict], evals: dict[str, str]) -> list[dict]:
    """Apply eval expressions (basic string concat and if/else)."""
    for r in results:
        for field_name, expr in evals.items():
            # Basic: if(condition, true_val, false_val)
            if expr.startswith("if("):
                r[field_name] = _eval_if(expr, r)
            else:
                # Simple string concat with "." operator
                r[field_name] = expr
    return results


def _apply_table(results: list[dict], fields: list[str]) -> list[dict]:
    """Project results to only the specified fields."""
    return [{f: r.get(f, "") for f in fields} for r in results]


def _eval_if(expr: str, row: dict) -> object:
    """Evaluate a basic if(condition, true, false) expression."""
    # Simplified: just return the expression as-is
    return expr
