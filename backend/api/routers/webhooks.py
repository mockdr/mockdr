"""Webhook subscription management endpoints.

GET    /web/api/v2.1/webhooks          — list all subscriptions
POST   /web/api/v2.1/webhooks          — create a new subscription
GET    /web/api/v2.1/webhooks/{id}     — get a single subscription
DELETE /web/api/v2.1/webhooks/{id}     — delete a subscription
"""
from fastapi import APIRouter, Depends, HTTPException

from api.auth import require_admin
from api.dto.requests import WebhookCreateBody, WebhookFireBody
from application.webhooks import commands as webhook_commands
from application.webhooks import queries as webhook_queries

router = APIRouter(tags=["Webhooks"])


@router.get("/webhooks")
def list_webhooks() -> dict:
    """Return all webhook subscriptions."""
    return webhook_queries.list_webhooks()


@router.post("/webhooks")
def create_webhook(body: WebhookCreateBody, _: dict = Depends(require_admin)) -> dict:
    """Create a new webhook subscription."""
    try:
        return webhook_commands.create_webhook(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/webhooks/{webhook_id}")
def get_webhook(webhook_id: str) -> dict:
    """Return a single webhook subscription by ID."""
    result = webhook_queries.get_webhook(webhook_id)
    if result is None:
        raise HTTPException(status_code=404)
    return result


@router.delete("/webhooks/{webhook_id}")
def delete_webhook(webhook_id: str, _: dict = Depends(require_admin)) -> dict:
    """Delete a webhook subscription by ID."""
    return webhook_commands.delete_webhook(webhook_id)


@router.post("/webhooks/fire")
def fire_webhook_event(body: WebhookFireBody, _: dict = Depends(require_admin)) -> dict:
    """Fire a test event to all matching active webhook subscriptions."""
    from domain.webhook import ALL_EVENT_TYPES  # noqa: PLC0415
    if body.event_type not in ALL_EVENT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid event_type: {body.event_type}")
    webhook_commands.fire_event(body.event_type, body.payload or {})
    return {"data": {"event_type": body.event_type, "fired": True}}
