"""DTO serializers for the playbook domain.

Converts domain objects to plain dicts suitable for inclusion in S1-style
API response envelopes.  This module is the single source of truth for the
playbook response shape — both the command side (which returns run results
immediately after starting execution) and the query side (which returns
current run status on poll) import from here.

No business logic lives here — only structural transformation.
"""
from application.playbook._run_state import PlaybookRun


def serialize_run(run: PlaybookRun) -> dict:
    """Serialise a ``PlaybookRun`` to a plain dict for API responses.

    Args:
        run: The playbook run instance to serialise.

    Returns:
        Dict suitable for inclusion in an S1-style ``{"data": ...}`` envelope.
        Keys: playbookId, agentId, status, currentStep, totalSteps,
        startedAt, completedAt, steps (list of step dicts).
    """
    return {
        "playbookId": run.playbookId,
        "agentId": run.agentId,
        "status": run.status,
        "currentStep": run.currentStep,
        "totalSteps": len(run.steps),
        "startedAt": run.startedAt,
        "completedAt": run.completedAt,
        "steps": [
            {
                "stepId": s.stepId,
                "status": s.status,
                "startedAt": s.startedAt,
                "completedAt": s.completedAt,
                "error": s.error,
            }
            for s in run.steps
        ],
    }
