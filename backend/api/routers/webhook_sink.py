"""Webhook sink endpoints — built-in receiver for closed-loop webhook testing."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request

from application.webhook_sink import commands, queries

# ── Public (no auth) — accepts incoming webhook deliveries ────────────────────
public_router = APIRouter(tags=["DEV"])


_MAX_BODY_BYTES = 1_048_576  # 1 MiB


@public_router.post("/_dev/webhook-sink")
async def receive_webhook(request: Request) -> dict:
    """Accept an incoming webhook delivery and store it in the sink.

    Reads the ``X-S1-Webhook-Event`` header to tag the event type.
    No authentication required so external webhook dispatchers can POST freely.
    Body is limited to 1 MiB to prevent abuse.
    """
    from fastapi import HTTPException

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large (max 1 MiB)")
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large (max 1 MiB)")
    import json
    body = json.loads(raw)
    event_type = request.headers.get("X-S1-Webhook-Event", "")
    headers = dict(request.headers)
    return commands.capture_webhook(event_type=event_type, headers=headers, body=body)


# ── Admin-gated — list and clear captured deliveries ──────────────────────────
router = APIRouter(tags=["DEV"])


@router.get("/_dev/webhook-sink")
def list_captured(limit: int = Query(100, ge=1, le=500)) -> dict:
    """Return captured webhook deliveries, newest first.

    Args:
        limit: Maximum number of entries to return.  Defaults to 100.
    """
    return queries.list_captured(limit=limit)


@router.delete("/_dev/webhook-sink")
def clear_sink() -> dict:
    """Delete all captured webhook deliveries from the sink."""
    return commands.clear_sink()
