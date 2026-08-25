"""Splunk HTTP Event Collector (HEC) router."""
from __future__ import annotations

import itertools

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from api.splunk_auth import require_hec_auth, require_splunk_auth
from application.splunk.commands.hec import submit_event, submit_events_batch, submit_raw
from repository.splunk.splunk_index_repo import splunk_index_repo
from utils.splunk.hec_validation import (
    ACK_DISABLED,
    INCORRECT_INDEX,
    NO_CHANNEL,
    NO_DATA,
    HecError,
    index_allowed,
    parse_hec_payload,
    require_channel,
    validate_event,
)

router = APIRouter(tags=["Splunk HEC"])

# Acknowledgement ids are per channel and monotonic in real HEC. Nothing was
# ever issued before, so the whole indexer-acknowledgement workflow — the
# reason a forwarder sets useACK at all — could not be exercised.
_ACK_COUNTERS: dict[str, itertools.count] = {}
_ISSUED_ACKS: dict[str, set[int]] = {}


def _next_ack(channel: str) -> int:
    counter = _ACK_COUNTERS.setdefault(channel, itertools.count())
    ack_id: int = next(counter)
    _ISSUED_ACKS.setdefault(channel, set()).add(ack_id)
    return ack_id


def _wants_ack(use_ack_param: str, token: dict) -> bool:
    if use_ack_param:
        return use_ack_param.strip().lower() in ("1", "true", "yes")
    return bool(token.get("use_ack"))


def _error_response(exc: HecError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.body())


def _ingest(text: str, hec_info: dict, channel: str | None, use_ack: bool) -> dict:
    """Validate and store an HEC payload, returning the HEC envelope."""
    require_channel(use_ack, channel)
    # Validated as each is parsed, so the first failing event in document
    # order is the one reported — even when a later one is not JSON at all.
    events = parse_hec_payload(
        text, on_event=lambda event, position: validate_event(event, hec_info, position),
    )

    if len(events) == 1:
        result = submit_event(
            events[0], hec_info["index"], hec_info.get("sourcetype", ""),
        )
    else:
        result = submit_events_batch(
            events, hec_info["index"], hec_info.get("sourcetype", ""),
        )

    if use_ack and channel:
        result = {**result, "ackId": _next_ack(channel)}
    return result


@router.post("/services/collector/event", response_model=None)
@router.post("/services/collector/event/1.0", response_model=None)
@router.post("/services/collector", response_model=None)
@router.post("/services/collector/1.0", response_model=None)
async def hec_event(
    request: Request,
    useACK: str = Query(default=""),  # noqa: N803 - HEC's own parameter name
    x_splunk_request_channel: str | None = Header(default=None),
    hec_info: dict = Depends(require_hec_auth),
) -> dict | JSONResponse:
    """Submit JSON-formatted event(s) via HEC."""
    body = await request.body()
    channel = x_splunk_request_channel or request.query_params.get("channel")
    try:
        return _ingest(
            body.decode("utf-8"),
            hec_info,
            channel,
            _wants_ack(useACK, hec_info),
        )
    except HecError as exc:
        return _error_response(exc)


@router.post("/services/collector/raw", response_model=None)
@router.post("/services/collector/raw/1.0", response_model=None)
async def hec_raw(
    request: Request,
    index: str = Query(default=""),
    sourcetype: str = Query(default=""),
    source: str = Query(default=""),
    host: str = Query(default="mockdr"),
    useACK: str = Query(default=""),  # noqa: N803 - HEC's own parameter name
    x_splunk_request_channel: str | None = Header(default=None),
    hec_info: dict = Depends(require_hec_auth),
) -> dict | JSONResponse:
    """Submit raw event text via HEC."""
    body = await request.body()
    raw_text = body.decode("utf-8")
    channel = x_splunk_request_channel or request.query_params.get("channel")
    use_ack = _wants_ack(useACK, hec_info)

    try:
        require_channel(use_ack, channel)
        if not raw_text.strip():
            # An empty raw body is code 5, not a silent success.
            raise HecError(*NO_DATA)
        if index and not index_allowed(index, hec_info):
            # A raw body is one event, at position 0.
            raise HecError(*INCORRECT_INDEX, event_number=0)
    except HecError as exc:
        return _error_response(exc)

    result = submit_raw(
        raw_text,
        index=index or hec_info["index"],
        sourcetype=sourcetype or hec_info.get("sourcetype", ""),
        source=source,
        host=host,
    )
    if use_ack and channel:
        result = {**result, "ackId": _next_ack(channel)}
    return result


@router.get("/services/collector/health")
@router.get("/services/collector/health/1.0")
def hec_health() -> dict:
    """HEC health check endpoint (no auth required)."""
    return {"text": "HEC is healthy", "code": 17}


@router.post("/services/collector/ack", response_model=None)
def hec_ack(
    body: dict = Body(default={}),
    x_splunk_request_channel: str | None = Header(default=None),
    hec_info: dict = Depends(require_hec_auth),
) -> dict | JSONResponse:
    """Check HEC indexing acknowledgment status."""
    channel_has_acks = bool(x_splunk_request_channel) and x_splunk_request_channel in _ISSUED_ACKS
    if not hec_info.get("use_ack") and not channel_has_acks:
        # A token without indexer acknowledgement has no acks to query;
        # splunkd says so (code 14) before it looks for a channel.
        return _error_response(HecError(*ACK_DISABLED))
    if not x_splunk_request_channel:
        return _error_response(HecError(*NO_CHANNEL))

    issued = _ISSUED_ACKS.get(x_splunk_request_channel, set())
    acks = body.get("acks", [])
    # Only ids this channel was actually given can be acknowledged; every id
    # used to come back True, including ones never issued.
    return {"acks": {str(ack_id): ack_id in issued for ack_id in acks}}


# ── The simple receiver ──────────────────────────────────────────────────────
#
# The other way in. HEC is the modern one, but `/services/receivers/simple`
# takes a raw body over the management port and every ad-hoc script and
# integration that predates HEC still uses it. mockdr answered 404, so an
# ingest that works against splunkd wrote nothing here and said so with a
# status a client reads as "wrong URL" rather than "not stored".
#
# splunkd answers with what it did rather than with "Success": the index it
# wrote to, how many bytes it took, and the host, source and sourcetype it
# stamped. All measured on 10.4.2, refusals included.

def _index_exists(name: str) -> bool:
    """Whether this instance holds the index a receiver was pointed at."""
    return any(idx.name == name for idx in splunk_index_repo.list_all())


#: What splunkd calls a body it was given no `source` for.
_SIMPLE_SOURCE = "http-simple"

#: How it names a sourcetype it could not work out. The suffix is its own
#: verdict on the payload — too small to guess from.
_SIMPLE_SOURCETYPE = "unknown-too_small"


@router.post("/services/receivers/simple", response_model=None)
async def receivers_simple(
    request: Request,
    index: str = Query(default="default"),
    sourcetype: str = Query(default=""),
    source: str = Query(default=""),
    host: str = Query(default=""),
    _user: dict = Depends(require_splunk_auth),
) -> JSONResponse:
    """Take a raw event body, the way splunkd's simple receiver does."""
    body = await request.body()
    if not body.strip():
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "WARN", "text": "empty body"},
        ]})
    if index != "default" and not _index_exists(index):
        raise HTTPException(status_code=400, detail={"messages": [
            {"type": "WARN", "text": f"supplied index '{index}' missing"},
        ]})

    text = body.decode("utf-8", errors="replace")
    stamped_host = host or (request.client.host if request.client else "127.0.0.1")
    stamped_source = source or _SIMPLE_SOURCE
    stamped_sourcetype = sourcetype or _SIMPLE_SOURCETYPE
    submit_event(
        {"event": text, "index": index, "sourcetype": stamped_sourcetype,
         "source": stamped_source, "host": stamped_host},
        index,
        stamped_sourcetype,
    )
    return JSONResponse(status_code=200, content={
        "index": index,
        "bytes": len(body),
        "host": stamped_host,
        "source": stamped_source,
        "sourcetype": stamped_sourcetype,
    })
