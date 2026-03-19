"""In-memory state for the active playbook execution (run lifecycle only).

Manages the single currently-running (or last completed) ``PlaybookRun``,
the threading lock that protects it, and the cancellation flag that the
executor thread polls.

This module has no knowledge of the playbook registry.  See ``_registry.py``
for the mutable catalogue of available playbooks.
"""
import threading
from dataclasses import dataclass, field


@dataclass
class StepResult:
    """Execution status of a single playbook step."""

    stepId: str  # noqa: N815
    status: str  # "pending" | "running" | "done" | "error"
    startedAt: str | None = None  # noqa: N815
    completedAt: str | None = None  # noqa: N815
    error: str | None = None


@dataclass
class PlaybookRun:
    """State of a single playbook execution instance."""

    playbookId: str  # noqa: N815
    agentId: str  # noqa: N815
    status: str  # "idle" | "running" | "done" | "cancelled" | "error"
    steps: list[StepResult] = field(default_factory=list)
    currentStep: int = 0  # noqa: N815
    startedAt: str | None = None  # noqa: N815
    completedAt: str | None = None  # noqa: N815


_lock = threading.Lock()
_run: PlaybookRun | None = None
_cancel_flag = threading.Event()


def get_run() -> PlaybookRun | None:
    """Return the current (or last completed) PlaybookRun, or None."""
    return _run


def set_run(run: PlaybookRun | None) -> None:
    """Replace the current run state atomically.

    Args:
        run: New run to set, or None to clear.
    """
    global _run
    with _lock:
        _run = run


def is_cancelled() -> bool:
    """Return True if a cancellation has been requested for the active run."""
    return _cancel_flag.is_set()


def request_cancel() -> None:
    """Signal the executor to stop the current run."""
    _cancel_flag.set()


def reset_cancel() -> None:
    """Clear the cancellation flag before starting a new run."""
    _cancel_flag.clear()
