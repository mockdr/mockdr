"""Non-SentinelOne endpoints for development tooling.

POST   /_dev/reset                   — re-seed all data
POST   /_dev/scenario                — trigger a named simulation scenario
GET    /_dev/tokens                  — list all valid API tokens
GET    /_dev/stats                   — counts for all collections
GET    /_dev/requests                — list recent request audit log entries
DELETE /_dev/requests                — clear the request audit log
GET    /_dev/export                  — export the full store to JSON
POST   /_dev/import                  — import a store snapshot
GET    /_dev/rate-limit              — get current rate-limit config
POST   /_dev/rate-limit              — update rate-limit config
GET    /_dev/playbooks               — list all playbooks
GET    /_dev/playbooks/status        — current execution status
GET    /_dev/playbooks/{id}          — playbook detail
POST   /_dev/playbooks/{id}/run      — start execution
DELETE /_dev/playbooks/cancel        — cancel active execution
POST   /_dev/playbooks               — create a custom playbook
PUT    /_dev/playbooks/{id}          — update a playbook
DELETE /_dev/playbooks/{id}          — delete a playbook
GET    /_dev/webhooks/deliveries     — recent webhook delivery log
GET    /_dev/fault-injection         — get current fault injection config
POST   /_dev/fault-injection         — update fault injection config
DELETE /_dev/fault-injection         — reset fault injection to defaults
GET    /_dev/export/logs             — unified structured log export (SIEM-ready)
GET    /_dev/graph/tokens            — list all Graph OAuth client credentials
POST   /_dev/graph/plan              — switch active Graph token plan on-the-fly
"""
from fastapi import APIRouter, Body, HTTPException, Query

from api.dto.playbook import PlaybookCreateBody, PlaybookUpdateBody
from api.dto.requests import (
    DevFaultInjectionBody,
    DevPlaybookRunBody,
    DevRateLimitBody,
    DevScenarioBody,
)
from api.middleware.rate_limit import get_config, reset_counters, set_config
from application.dev import commands as dev_commands
from application.dev import queries as dev_queries
from application.playbook import commands as playbook_commands
from application.playbook import queries as playbook_queries
from application.request_log import commands as request_log_commands
from application.request_log import queries as request_log_queries
from application.webhooks import queries as webhook_queries

router = APIRouter(tags=["DEV"])


@router.post("/_dev/reset")
def reset() -> dict:
    """Re-seed all in-memory data to the initial generated state."""
    return dev_commands.reset()


@router.post("/_dev/scenario")
def trigger_scenario(body: DevScenarioBody) -> dict:
    """Trigger a named simulation scenario affecting agents and threats."""
    return dev_commands.trigger_scenario(body.scenario)


@router.get("/_dev/tokens")
def get_tokens() -> dict:
    """Return all active API tokens stored in the mock."""
    return dev_queries.list_tokens()


@router.get("/_dev/stats")
def get_stats() -> dict:
    """Return record counts for every store collection."""
    return dev_queries.get_stats()


# ── Request Audit Log ─────────────────────────────────────────────────────────

@router.get("/_dev/requests")
def list_requests(limit: int = Query(100, ge=1, le=1000)) -> dict:
    """Return the most recent HTTP request audit log entries.

    Args:
        limit: Maximum number of entries to return (default 100).

    Returns:
        Dict with ``data`` list and ``pagination.totalItems``.
    """
    return request_log_queries.list_request_logs(limit=limit)


@router.delete("/_dev/requests")
def clear_requests() -> dict:
    """Clear all HTTP request audit log entries.

    Returns:
        Dict with ``data.affected`` indicating how many entries were deleted.
    """
    return request_log_commands.clear_request_logs()


# ── Export / Import ───────────────────────────────────────────────────────────

@router.get("/_dev/export")
def export_state() -> dict:
    """Export the full in-memory store as a JSON-safe snapshot.

    Returns:
        Dict mapping each collection name to its list of records.
    """
    return dev_commands.export_state()


@router.post("/_dev/import")
def import_state(body: dict) -> dict:
    """Replace the entire store with the provided snapshot.

    Args:
        body: Snapshot dict as returned by ``GET /_dev/export``.

    Returns:
        Dict with ``data.imported`` indicating the total records loaded.
    """
    return dev_commands.import_state(body)


# ── Rate-Limit Config ─────────────────────────────────────────────────────────

@router.get("/_dev/rate-limit")
def get_rate_limit() -> dict:
    """Return the current rate-limit configuration.

    Returns:
        Dict with ``enabled`` and ``requestsPerMinute`` fields.
    """
    cfg = get_config()
    return {"enabled": cfg.enabled, "requestsPerMinute": cfg.requests_per_minute}


@router.post("/_dev/rate-limit")
def set_rate_limit(body: DevRateLimitBody) -> dict:
    """Update the rate-limit configuration."""
    set_config(enabled=body.enabled, rpm=body.requestsPerMinute)
    reset_counters()
    return {"enabled": body.enabled, "requestsPerMinute": body.requestsPerMinute}


# ── Playbooks ──────────────────────────────────────────────────────────────

@router.get("/_dev/playbooks")
def list_playbooks() -> dict:
    """List all available playbooks (builtins and user-created)."""
    return playbook_queries.list_playbooks()


@router.get("/_dev/playbooks/status")
def playbook_status() -> dict:
    """Return the status of the currently running (or last) playbook execution."""
    return playbook_queries.get_status()


@router.get("/_dev/playbooks/{playbook_id}")
def get_playbook(playbook_id: str) -> dict:
    """Return full detail for a playbook including all steps.

    Args:
        playbook_id: The playbook's unique identifier.

    Raises:
        HTTPException: 404 if the playbook is not found.
    """
    result = playbook_queries.get_playbook_detail(playbook_id)
    if not result:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.post("/_dev/playbooks/{playbook_id}/run")
def run_playbook(playbook_id: str, body: DevPlaybookRunBody) -> dict:
    """Start a playbook execution against a specific agent."""
    return {"data": playbook_commands.run_playbook(playbook_id, body.agentId)}


@router.delete("/_dev/playbooks/cancel")
def cancel_playbook() -> dict:
    """Cancel the currently running playbook."""
    return {"data": playbook_commands.cancel_playbook()}


@router.post("/_dev/playbooks")
def create_playbook(body: PlaybookCreateBody) -> dict:
    """Create a new custom playbook.

    Body: ``{ title, description, category, severity, estimatedDurationMs, steps }``
    """
    return playbook_commands.create_playbook(body.model_dump())


@router.put("/_dev/playbooks/{playbook_id}")
def update_playbook(playbook_id: str, body: PlaybookUpdateBody) -> dict:
    """Update an existing playbook by ID.

    Body: partial or full playbook dict; ``id`` is ignored if present.

    Raises:
        HTTPException: 404 if no playbook with the given ID exists.
    """
    result = playbook_commands.update_playbook(playbook_id, body.model_dump(exclude_none=True))
    if result is None:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return result


@router.delete("/_dev/playbooks/{playbook_id}")
def delete_playbook(playbook_id: str) -> dict:
    """Delete a playbook by ID.

    Returns ``{"data": {"affected": 1}}`` on success or
    ``{"data": {"affected": 0}}`` if the ID was not found.
    """
    return playbook_commands.delete_playbook(playbook_id)


# ── Webhook Delivery Log ─────────────────────────────────────────────────────

@router.get("/_dev/webhooks/deliveries")
def list_webhook_deliveries() -> dict:
    """Return recent webhook delivery log entries (newest first).

    Capped at 100 entries.  Useful for debugging webhook delivery
    and retry behaviour.
    """
    return webhook_queries.list_deliveries()


# ── Fault Injection ──────────────────────────────────────────────────────────

@router.get("/_dev/fault-injection")
def get_fault_injection() -> dict:
    """Return the current fault injection configuration.

    Returns:
        Dict with delay and error injection settings.
    """
    from api.middleware.fault_injection import get_fault_config
    cfg = get_fault_config()
    return {
        "delayMs": cfg.delay_ms,
        "delayJitterMs": cfg.delay_jitter_ms,
        "errorRate": cfg.error_rate,
        "errorStatus": cfg.error_status,
    }


@router.post("/_dev/fault-injection")
def set_fault_injection(body: DevFaultInjectionBody) -> dict:
    """Update fault injection configuration.

    Set ``delayMs`` > 0 to add artificial latency. Set ``errorRate`` > 0
    to make a fraction of requests return errors.
    """
    from api.middleware.fault_injection import set_fault_config
    cfg = set_fault_config(
        delay_ms=body.delayMs,
        delay_jitter_ms=body.delayJitterMs,
        error_rate=body.errorRate,
        error_status=body.errorStatus,
    )
    return {
        "delayMs": cfg.delay_ms,
        "delayJitterMs": cfg.delay_jitter_ms,
        "errorRate": cfg.error_rate,
        "errorStatus": cfg.error_status,
    }


@router.delete("/_dev/fault-injection")
def reset_fault_injection() -> dict:
    """Reset fault injection to defaults (all disabled)."""
    from api.middleware.fault_injection import reset_fault_config
    reset_fault_config()
    return {"data": {"status": "fault injection reset"}}


# ── Structured Log Export ────────────────────────────────────────────────────

@router.get("/_dev/export/logs")
def export_logs(format: str = "json") -> dict:
    """Export all audit, delivery, and webhook sink logs in a unified format.

    Useful for testing SIEM log ingestion pipelines against MockDR's own
    operational data.

    Args:
        format: Output format — ``json`` (default) returns a dict with
            categorised log arrays.

    Returns:
        Dict with ``request_logs``, ``webhook_deliveries``, and
        ``webhook_sink`` arrays, each entry tagged with ``_log_type``.
    """
    from application.webhook_sink import queries as sink_queries

    request_logs = request_log_queries.list_request_logs(limit=500)
    deliveries = webhook_queries.list_deliveries()
    sink = sink_queries.list_captured(limit=500)

    # Tag each entry with its log type for unified ingestion
    for entry in request_logs.get("data", []):
        entry["_log_type"] = "request_audit"
    for entry in deliveries.get("data", []):
        entry["_log_type"] = "webhook_delivery"
    for entry in sink.get("data", []):
        entry["_log_type"] = "webhook_sink"

    return {
        "data": {
            "request_logs": request_logs.get("data", []),
            "webhook_deliveries": deliveries.get("data", []),
            "webhook_sink": sink.get("data", []),
        },
        "pagination": {
            "totalItems": (
                request_logs.get("pagination", {}).get("totalItems", 0)
                + len(deliveries.get("data", []))
                + sink.get("pagination", {}).get("totalItems", 0)
            ),
        },
    }


# ── Microsoft Graph DEV endpoints ────────────────────────────────────────────

@router.get("/_dev/graph/tokens")
def graph_tokens() -> dict:
    """Return all Graph OAuth client credentials for easy copy-paste."""
    from repository.store import store

    clients = store.get_all("graph_oauth_clients")
    return {
        "data": [
            {
                "client_id": c.client_id,
                "client_secret": c.client_secret,
                "plan": c.plan,
                "role": c.role,
            }
            for c in clients
        ]
    }


@router.post("/_dev/graph/plan")
def switch_graph_plan(body: dict = Body(...)) -> dict:
    """Change the plan of all active Graph tokens on-the-fly.

    Body: ``{ "plan": "plan1" | "plan2" | "defender_for_business" | "none" }``
    """
    from repository.store import store

    plan = body.get("plan", "plan2")
    tokens = store.get_all("graph_oauth_tokens")
    for token_record in tokens:
        if isinstance(token_record, dict):
            token_record["plan"] = plan
            store.save("graph_oauth_tokens", token_record["access_token"], token_record)
        else:
            token_record.plan = plan
            key = getattr(token_record, "access_token", getattr(token_record, "id", ""))
            store.save("graph_oauth_tokens", key, token_record)
    return {"data": {"plan": plan, "tokens_updated": len(tokens)}}
