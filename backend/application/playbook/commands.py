"""Playbook command handlers (write side of CQRS).

All functions in this module mutate state — either the playbook registry or
the active run.  No read-only queries belong here, and this module must not
be imported by ``queries.py``.

Run serialisation is delegated to ``_dto.py`` so the response shape stays
consistent with the query side without crossing the CQRS boundary.
"""
from application.playbook import executor
from application.playbook._dto import serialize_run
from application.playbook._registry import (
    delete_from_registry,
    get_from_registry,
    save_to_registry,
)
from utils.dt import utc_now
from utils.id_gen import new_id

# ── Run commands ───────────────────────────────────────────────────────────────

def run_playbook(playbook_id: str, agent_id: str) -> dict:
    """Start executing a playbook against a specific agent.

    Args:
        playbook_id: ID of the playbook to execute (must exist in the registry).
        agent_id: ID of the agent to target.

    Returns:
        Serialised ``PlaybookRun`` dict, or a dict with an ``error`` key if the
        playbook ID is unknown.
    """
    playbook = get_from_registry(playbook_id)
    if not playbook:
        return {"error": f"Unknown playbook: {playbook_id}"}
    run = executor.start(playbook, agent_id)
    return serialize_run(run)


def cancel_playbook() -> dict:
    """Request cancellation of the currently running playbook.

    Returns:
        Dict with ``cancelled`` bool indicating whether a run was active.
    """
    cancelled = executor.cancel()
    return {"cancelled": cancelled}


# ── CRUD commands ──────────────────────────────────────────────────────────────

def create_playbook(data: dict) -> dict:
    """Create a new custom playbook and add it to the registry.

    If ``data`` contains an ``id`` key it is used as-is; otherwise a
    SentinelOne-style numeric ID is generated via ``new_id()``.

    Args:
        data: Dict with fields: title, description, category, severity,
              estimatedDurationMs, steps.  All fields are optional and default
              to sensible values.

    Returns:
        Dict with ``data`` key containing the created playbook record.
    """
    now = utc_now()
    playbook: dict = {
        "id": data.get("id") or new_id(),
        "title": data.get("title", "Untitled"),
        "description": data.get("description", ""),
        "category": data.get("category", "custom"),
        "severity": data.get("severity", "MEDIUM"),
        "estimatedDurationMs": int(data.get("estimatedDurationMs", 10000)),
        "steps": data.get("steps", []),
        "builtin": False,
        "createdAt": now,
        "updatedAt": now,
    }
    save_to_registry(playbook)
    return {"data": playbook}


def update_playbook(playbook_id: str, data: dict) -> dict | None:
    """Update an existing playbook in the registry.

    Only the fields present in ``data`` are overwritten; all other fields
    retain their current values.  The ``id`` field is never overwritten.

    Args:
        playbook_id: ID of the playbook to update.
        data: Partial or full playbook dict.  The ``id`` key is ignored.

    Returns:
        Dict with ``data`` key containing the updated playbook, or None if
        the playbook does not exist.
    """
    existing = get_from_registry(playbook_id)
    if not existing:
        return None
    updated: dict = {
        **existing,
        "title": data.get("title", existing["title"]),
        "description": data.get("description", existing["description"]),
        "category": data.get("category", existing["category"]),
        "severity": data.get("severity", existing["severity"]),
        "estimatedDurationMs": int(
            data.get("estimatedDurationMs", existing["estimatedDurationMs"])
        ),
        "steps": data.get("steps", existing["steps"]),
        "updatedAt": utc_now(),
    }
    save_to_registry(updated)
    return {"data": updated}


def delete_playbook(playbook_id: str) -> dict:
    """Remove a playbook from the registry.

    Args:
        playbook_id: ID of the playbook to delete.

    Returns:
        Dict with ``data.affected`` = 1 if deleted, 0 if not found.
    """
    deleted = delete_from_registry(playbook_id)
    return {"data": {"affected": 1 if deleted else 0}}
