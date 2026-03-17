"""Playbook query handlers (read side of CQRS).

All functions here are pure reads — they do not mutate any state, and this
module must not import from ``commands.py``.

Run serialisation is imported from ``_dto.py``, which is the shared boundary
between the command and query sides.
"""
from application.playbook._dto import serialize_run
from application.playbook._registry import get_from_registry, list_registry
from application.playbook._run_state import get_run


def list_playbooks() -> dict:
    """Return summary metadata for all playbooks in the registry.

    Returns:
        Dict with ``data`` key containing a list of playbook summary records.
        Each record exposes: id, title, description, category, severity,
        estimatedDurationMs, stepCount, builtin.
    """
    return {
        "data": [
            {
                "id": p["id"],
                "title": p["title"],
                "description": p["description"],
                "category": p["category"],
                "severity": p["severity"],
                "estimatedDurationMs": p["estimatedDurationMs"],
                "stepCount": len(p["steps"]),
                "builtin": p.get("builtin", True),
            }
            for p in list_registry()
        ]
    }


def get_status() -> dict:
    """Return the status of the current (or last completed) playbook run.

    Returns:
        Dict with ``data`` containing the run state, or ``{"status": "idle"}``
        if no run has been started.
    """
    run = get_run()
    if not run:
        return {"data": {"status": "idle"}}
    return {"data": serialize_run(run)}


def get_playbook_detail(playbook_id: str) -> dict | None:
    """Return the full detail of a single playbook including all steps.

    Args:
        playbook_id: The playbook's unique identifier.

    Returns:
        Dict with ``data`` containing the full playbook dict, or None if not
        found.
    """
    p = get_from_registry(playbook_id)
    if not p:
        return None
    return {"data": p}
