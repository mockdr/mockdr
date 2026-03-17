"""Mutable in-memory registry of all available playbooks.

Seeded from ``_builtins.BUILTIN_PLAYBOOKS`` at import time and reset to that
baseline by ``reset_registry()`` — called by ``infrastructure.seed.generate_all``
to guarantee test isolation.

This module has no knowledge of run execution state.  See ``_run_state.py``
for the active-run lifecycle.
"""
import copy
import threading

from application.playbook._builtins import BUILTIN_PLAYBOOKS

_lock = threading.Lock()
_registry: dict[str, dict] = {str(p["id"]): copy.deepcopy(p) for p in BUILTIN_PLAYBOOKS}


def list_registry() -> list[dict]:
    """Return a stable snapshot of all playbooks in the registry.

    Returns:
        List of playbook dicts (builtins and user-created alike).
    """
    with _lock:
        return list(_registry.values())


def get_from_registry(playbook_id: str) -> dict | None:
    """Look up a single playbook by ID.

    Args:
        playbook_id: The playbook's unique string identifier.

    Returns:
        The playbook dict, or None if not found.
    """
    with _lock:
        return _registry.get(playbook_id)


def save_to_registry(playbook: dict) -> None:
    """Insert or replace a playbook in the registry.

    Args:
        playbook: Playbook dict; must contain an ``id`` key.
    """
    with _lock:
        _registry[playbook["id"]] = playbook


def delete_from_registry(playbook_id: str) -> bool:
    """Remove a playbook from the registry.

    Args:
        playbook_id: The ID of the playbook to remove.

    Returns:
        True if the playbook existed and was removed, False otherwise.
    """
    with _lock:
        return _registry.pop(playbook_id, None) is not None


def reset_registry() -> None:
    """Restore the registry to the built-in set.

    Called by ``infrastructure.seed.generate_all()`` before each test to
    ensure that user-created or deleted playbooks never leak between test cases.
    """
    with _lock:
        _registry.clear()
        _registry.update({str(p["id"]): copy.deepcopy(p) for p in BUILTIN_PLAYBOOKS})
