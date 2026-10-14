"""Webhook sink endpoints — built-in receiver for closed-loop webhook testing."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request

from application.webhook_sink import commands, queries

# ── Public (no auth) — accepts incoming webhook deliveries ────────────────────
public_router = APIRouter(tags=["DEV"])


_SECRET_HEADERS = frozenset({"authorization", "cookie", "x-api-key", "x-sentinelone-token"})
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
    # The sink is unauthenticated. A non-numeric Content-Length used to raise
    # ValueError here and answer 500 to anyone who sent one.
    if content_length and content_length.isdigit() and int(content_length) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large (max 1 MiB)")
    raw = await request.body()
    if len(raw) > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large (max 1 MiB)")
    import json
    try:
        body = json.loads(raw)
    except RecursionError as exc:
        # A body of nested brackets reached Python's recursion limit and
        # answered 500 to anyone who asked.
        raise HTTPException(status_code=400, detail="Request body is nested too deeply") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Request body is not valid JSON") from exc
    event_type = request.headers.get("X-S1-Webhook-Event", "")
    # The sink is public (it receives what the mock's own webhooks send), and
    # its entries are read by admins; a credential a sender attached must not
    # travel from the one to the other.
    headers = {
        k: ("<redacted>" if k.lower() in _SECRET_HEADERS else v) for k, v in request.headers.items()
    }
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
