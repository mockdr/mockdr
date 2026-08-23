"""Write-only application commands for webhook subscriptions and event delivery."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import asdict
from typing import Any

import httpx

from application.webhooks.delivery_log import DeliveryEntry
from application.webhooks.delivery_log import record as record_delivery
from domain.webhook import ALL_EVENT_TYPES, WebhookSubscription
from repository.webhook_repo import webhook_repo
from utils.dt import utc_now
from utils.id_gen import new_id
from utils.internal_fields import AGENT_INTERNAL_FIELDS

logger = logging.getLogger(__name__)

# Retry configuration
class _DeliveryPool:
    """A fixed set of daemon threads draining a queue of delivery calls."""

    def __init__(self, workers: int) -> None:
        self._queue: queue.Queue[tuple[Callable[..., None], tuple[object, ...]]] = queue.Queue()
        self._open = 0  # submitted, not yet finished
        self._cv = threading.Condition()
        for n in range(workers):
            threading.Thread(
                target=self._run, name=f"webhook-{n}", daemon=True
            ).start()

    def submit(self, fn: Callable[..., None], *args: object) -> None:
        with self._cv:
            self._open += 1
        self._queue.put((fn, args))

    def wait(self, timeout: float) -> None:
        with self._cv:
            self._cv.wait_for(lambda: self._open == 0, timeout=timeout)

    def _run(self) -> None:
        while True:
            fn, args = self._queue.get()
            try:
                fn(*args)
            except Exception:  # noqa: BLE001 - a worker must outlive any delivery
                logger.exception("Webhook delivery crashed")
            finally:
                with self._cv:
                    self._open -= 1
                    self._cv.notify_all()


MAX_RETRIES = 3
BACKOFF_BASE = 1  # seconds; delays will be 1s, 2s, 4s

# Deliveries run on a bounded pool of daemon workers: a scenario that fires
# hundreds of events at several receivers queues, instead of starting a
# sleeping thread per subscription per event — and shutdown never waits on
# a receiver (ThreadPoolExecutor's threads would be joined at exit).
_DELIVERIES = _DeliveryPool(workers=8)

# Fields present on mock domain objects that are NOT part of the real S1 API.
# Stripped from every webhook delivery so the payload matches the real format.
_THREAT_INTERNAL_FIELDS: frozenset[str] = frozenset({"notes", "timeline", "_fetched_file"})
_AGENT_INTERNAL_FIELDS: frozenset[str] = frozenset(AGENT_INTERNAL_FIELDS)


def create_webhook(body: dict, user_id: str | None = None) -> dict:
    """Create a new webhook subscription.

    Args:
        body: Dict containing ``url``, ``eventTypes``, and optionally
            ``secret``, ``active``, and ``description``.
        user_id: ID of the creating user, if authenticated.

    Returns:
        Dict with ``data`` containing the created subscription.

    Raises:
        ValueError: If any provided event type is not a valid event type.
    """
    event_types: list[str] = body.get("eventTypes", body.get("event_types", []))
    invalid = [et for et in event_types if et not in ALL_EVENT_TYPES]
    if invalid:
        raise ValueError(f"Invalid event types: {invalid}")

    now = utc_now()
    sub = WebhookSubscription(
        id=new_id(),
        url=body.get("url", ""),
        eventTypes=event_types,
        secret=body.get("secret", ""),
        active=body.get("active", True),
        description=body.get("description", ""),
        createdAt=now,
        updatedAt=now,
    )
    webhook_repo.save(sub)
    result = asdict(sub)
    if result.get("secret"):
        result["secret"] = "****" + result["secret"][-4:] if len(result["secret"]) >= 4 else "****"
    return {"data": result}


def delete_webhook(webhook_id: str) -> dict:
    """Delete a webhook subscription by ID.

    Args:
        webhook_id: The ID of the subscription to delete.

    Returns:
        Dict with ``data.affected`` being 1 if deleted, 0 if not found.
    """
    deleted = webhook_repo.delete(webhook_id)
    return {"data": {"affected": 1 if deleted else 0}}


def _build_headers(event_type: str, sub: WebhookSubscription, body_json: str) -> dict[str, str]:
    """Build HTTP headers for a webhook delivery."""
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "X-S1-Webhook-Event": event_type,
    }
    if sub.secret:
        headers["Authorization"] = f"Bearer {sub.secret}"
        sig = hmac.new(
            sub.secret.encode(),
            body_json.encode(),
            hashlib.sha256,
        ).hexdigest()
        headers["X-S1-Signature"] = f"sha256={sig}"
    return headers


def _deliver_with_retries(
    event_type: str,
    sub: WebhookSubscription,
    body_json: str,
    headers: dict[str, str],
) -> None:
    """Attempt delivery with exponential backoff retries.

    Runs up to ``MAX_RETRIES`` attempts.  On each failure the thread sleeps
    for ``BACKOFF_BASE * 2^(attempt-1)`` seconds before retrying.
    Each attempt (including the initial one) is recorded in the delivery log.

    This function is designed to run in a background thread so retries do
    not block the original request.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = httpx.post(sub.url, content=body_json, headers=headers, timeout=5.0)
            # A receiver that answers 5xx did not take the event; 4xx means it
            # never will. Only a 2xx/3xx is a delivery.
            if response.status_code >= 500:
                raise httpx.HTTPStatusError(
                    f"receiver answered {response.status_code}",
                    request=response.request,
                    response=response,
                )
            if response.status_code >= 400:
                record_delivery(DeliveryEntry(
                    subscription_id=sub.id,
                    event_type=event_type,
                    status="failure",
                    attempt=attempt,
                    timestamp=utc_now(),
                    error=f"receiver answered {response.status_code}",
                ))
                logger.error(
                    "Webhook rejected (%d) for %s → %s", response.status_code, event_type, sub.url
                )
                return
            record_delivery(DeliveryEntry(
                subscription_id=sub.id,
                event_type=event_type,
                status="success",
                attempt=attempt,
                timestamp=utc_now(),
            ))
            logger.info(
                "Webhook delivered on attempt %d for %s → %s",
                attempt, event_type, sub.url,
            )
            return
        except Exception as exc:  # noqa: BLE001
            record_delivery(DeliveryEntry(
                subscription_id=sub.id,
                event_type=event_type,
                status="failure",
                attempt=attempt,
                timestamp=utc_now(),
                error=str(exc),
            ))
            if attempt < MAX_RETRIES:
                delay = BACKOFF_BASE * (2 ** (attempt - 1))
                logger.warning(
                    "Webhook delivery attempt %d/%d failed for %s → %s, "
                    "retrying in %ds: %s",
                    attempt, MAX_RETRIES, event_type, sub.url, delay, exc,
                )
                time.sleep(delay)
            else:
                logger.error(
                    "Webhook delivery failed after %d attempts for %s → %s: %s",
                    MAX_RETRIES, event_type, sub.url, exc,
                )


def fire_event(event_type: str, payload: dict[str, Any]) -> None:
    """Deliver an event to all active subscriptions for the given event type.

    The POST body is the raw domain object (same shape as the REST API response
    for that resource), matching the SentinelOne "Full Details" webhook format.

    Authentication mirrors real SentinelOne behaviour: the secret is sent as
    ``Authorization: Bearer <secret>``.  In addition, an HMAC-SHA256 signature
    is included in ``X-S1-Signature`` for receivers that prefer it.

    Delivery uses background threads with up to 3 retry attempts and
    exponential backoff (1s, 2s, 4s).  Each attempt is logged in the
    in-memory delivery log.

    Args:
        event_type: The event type string, e.g. ``"threat.updated"``.
        payload: The domain object dict to use as the POST body.
    """
    subscriptions = webhook_repo.get_active_for_event(event_type)
    if not subscriptions:
        return

    # Strip mock-internal fields so the payload matches the real S1 API shape.
    if event_type in {"threat.created", "threat.updated"}:
        payload = {k: v for k, v in payload.items() if k not in _THREAT_INTERNAL_FIELDS}
    elif event_type in {"agent.offline", "agent.infected"}:
        payload = {k: v for k, v in payload.items() if k not in _AGENT_INTERNAL_FIELDS}

    # Body is the raw object — no envelope wrapper — matching real S1 format.
    body_json = json.dumps(payload, default=str)

    for sub in subscriptions:
        headers = _build_headers(event_type, sub, body_json)
        _DELIVERIES.submit(_deliver_with_retries, event_type, sub, body_json, headers)


def wait_for_deliveries(timeout: float = 5.0) -> None:
    """Block until every submitted delivery has finished (tests)."""
    _DELIVERIES.wait(timeout)
