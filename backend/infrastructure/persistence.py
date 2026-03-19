"""Optional JSON file persistence for the in-memory store.

When enabled via MOCKDR_PERSIST env var, store mutations are
debounced and written to a JSON file.  On startup the file is
loaded instead of seeding.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_DEBOUNCE_SECONDS = 2.0


class PersistenceManager:
    """Debounced JSON file persistence for store state."""

    def __init__(self, path: Path) -> None:
        """Initialize persistence with the given JSON file path."""
        self._path = path
        self._timer: threading.Timer | None = None
        self._lock = threading.Lock()

    def load_if_exists(self) -> bool:
        """Load state from file if it exists.

        Returns:
            True if state was loaded, False otherwise.
        """
        if not self._path.exists():
            return False
        try:
            with open(self._path) as f:
                snapshot = json.load(f)
            from application.dev.commands import import_state
            import_state(snapshot)
            logger.info("Loaded persisted state from %s", self._path)
            return True
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load %s, will seed fresh", self._path, exc_info=True)
            return False

    def schedule_save(self) -> None:
        """Schedule a debounced save. Resets timer on each call."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
            self._timer = threading.Timer(_DEBOUNCE_SECONDS, self._do_save)
            self._timer.daemon = True
            self._timer.start()

    def _do_save(self) -> None:
        """Write the current store state to file atomically."""
        try:
            from application.dev.commands import export_state
            from repository.store import store as _store
            with _store._lock:
                snapshot = export_state()
            dir_path = self._path.parent
            dir_path.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(snapshot, f, default=str)
                os.replace(tmp_path, self._path)
            except BaseException:
                os.unlink(tmp_path)
                raise
            logger.debug("Persisted state to %s", self._path)
        except Exception:
            logger.error("Failed to persist state to %s", self._path, exc_info=True)

    def flush(self) -> None:
        """Immediately save (for shutdown). Cancel any pending timer."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self._do_save()


_manager: PersistenceManager | None = None


def init_persistence(path: str) -> PersistenceManager:
    """Initialize the persistence manager singleton."""
    global _manager
    _manager = PersistenceManager(Path(path))
    return _manager


def notify_mutation() -> None:
    """Called after store mutations. No-op if persistence is disabled."""
    if _manager is not None:
        _manager.schedule_save()
