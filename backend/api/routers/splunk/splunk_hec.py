"""Splunk HTTP Event Collector (HEC) router."""
from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from api.splunk_auth import require_hec_auth
from application.splunk.commands.hec import submit_event, submit_events_batch, submit_raw

router = APIRouter(tags=["Splunk HEC"])


def _parse_hec_events(text: str) -> list[dict]:
    """Parse newline-delimited JSON from raw HEC request body.

    Args:
        text: The raw request body text (may contain multiple JSON objects
              separated by newlines).

    Returns:
        List of parsed event dicts.

    Raises:
        HTTPException: 400 if any line contains invalid JSON or body is empty.
    """
    events: list[dict] = []
    for line in text.split("\n"):
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=400, detail={"text": "Invalid JSON", "code": 6},
                ) from exc
    if not events:
        raise HTTPException(status_code=400, detail={"text": "No data", "code": 5})
    return events


def _submit_parsed_events(events: list[dict], hec_info: dict) -> dict:
    """Submit parsed HEC events to the store.

    Args:
        events:   List of parsed event dicts (must be non-empty).
        hec_info: HEC token info dict with ``index`` and ``sourcetype`` keys.

    Returns:
        Splunk HEC response dict.
    """
    if len(events) == 1:
        return submit_event(events[0], hec_info["index"], hec_info.get("sourcetype", ""))
    return submit_events_batch(events, hec_info["index"], hec_info.get("sourcetype", ""))


@router.post("/services/collector/event")
async def hec_event(
    request: Request,
    hec_info: dict = Depends(require_hec_auth),
) -> dict:
    """Submit JSON-formatted event(s) via HEC."""
    body = await request.body()
    text = body.decode("utf-8").strip()
    events = _parse_hec_events(text)
    return _submit_parsed_events(events, hec_info)


@router.post("/services/collector/raw")
async def hec_raw(
    request: Request,
    index: str = Query(default=""),
    sourcetype: str = Query(default=""),
    source: str = Query(default=""),
    host: str = Query(default="mockdr"),
    hec_info: dict = Depends(require_hec_auth),
) -> dict:
    """Submit raw event text via HEC."""
    body = await request.body()
    raw_text = body.decode("utf-8")
    return submit_raw(
        raw_text,
        index=index or hec_info["index"],
        sourcetype=sourcetype or hec_info.get("sourcetype", ""),
        source=source,
        host=host,
    )


@router.post("/services/collector")
async def hec_event_alias(
    request: Request,
    hec_info: dict = Depends(require_hec_auth),
) -> dict:
    """Alias for /services/collector/event."""
    body = await request.body()
    text = body.decode("utf-8").strip()
    events = _parse_hec_events(text)
    return _submit_parsed_events(events, hec_info)


@router.get("/services/collector/health")
def hec_health() -> dict:
    """HEC health check endpoint (no auth required)."""
    return {"text": "HEC is healthy", "code": 17}


@router.post("/services/collector/ack")
def hec_ack(
    body: dict = Body(default={}),
    hec_info: dict = Depends(require_hec_auth),
) -> dict:
    """Check HEC indexing acknowledgment status."""
    acks = body.get("acks", [])
    # All events are immediately indexed in mock
    return {"acks": {str(ack_id): True for ack_id in acks}}
