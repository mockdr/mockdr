"""Splunk HEC (HTTP Event Collector) command handlers."""
from __future__ import annotations

import json
import time
import uuid

from domain.splunk.splunk_event import SplunkEvent
from repository.splunk.splunk_event_repo import splunk_event_repo
from repository.splunk.splunk_index_repo import splunk_index_repo


def submit_event(
    event_data: dict,
    default_index: str = "main",
    default_sourcetype: str = "",
) -> dict:
    """Submit a single HEC JSON event.

    Args:
        event_data:        The HEC event payload (with event, index, sourcetype, etc.).
        default_index:     Default index from HEC token.
        default_sourcetype: Default sourcetype from HEC token.

    Returns:
        HEC success response dict.
    """
    event_body = event_data.get("event", event_data)
    index = event_data.get("index", default_index) or default_index
    sourcetype = event_data.get("sourcetype", default_sourcetype) or default_sourcetype
    source = event_data.get("source", "")
    host = event_data.get("host", "mockdr")
    event_time = event_data.get("time", time.time())

    if isinstance(event_body, dict):
        raw = json.dumps(event_body)
        fields = dict(event_body)
    else:
        raw = str(event_body)
        fields = {}

    event = SplunkEvent(
        id=str(uuid.uuid4()),
        index=index,
        sourcetype=sourcetype,
        source=source,
        host=host,
        time=float(event_time),
        raw=raw,
        fields=fields,
    )
    splunk_event_repo.save(event)
    _update_index_count(index)

    return {"text": "Success", "code": 0}


def submit_events_batch(
    events: list[dict],
    default_index: str = "main",
    default_sourcetype: str = "",
) -> dict:
    """Submit multiple HEC events.

    Args:
        events:            List of HEC event payloads.
        default_index:     Default index from HEC token.
        default_sourcetype: Default sourcetype from HEC token.

    Returns:
        HEC success response dict.
    """
    for event_data in events:
        submit_event(event_data, default_index, default_sourcetype)
    return {"text": "Success", "code": 0}


def submit_raw(
    raw_text: str,
    index: str = "main",
    sourcetype: str = "",
    source: str = "",
    host: str = "mockdr",
) -> dict:
    """Submit a raw text event.

    Args:
        raw_text:   Raw event text.
        index:      Target index.
        sourcetype: Sourcetype.
        source:     Source.
        host:       Host.

    Returns:
        HEC success response dict.
    """
    event = SplunkEvent(
        id=str(uuid.uuid4()),
        index=index,
        sourcetype=sourcetype,
        source=source,
        host=host,
        time=time.time(),
        raw=raw_text,
        fields={},
    )
    splunk_event_repo.save(event)
    _update_index_count(index)
    return {"text": "Success", "code": 0}


def _update_index_count(index_name: str) -> None:
    """Increment the event count for an index."""
    idx = splunk_index_repo.get(index_name)
    if idx:
        idx.total_event_count = splunk_event_repo.count_by_index(index_name)
        splunk_index_repo.save(idx)
