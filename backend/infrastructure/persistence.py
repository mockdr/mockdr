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
            if not isinstance(snapshot, dict):
                # A JSON array/scalar reached import_state as `snapshot.get(...)`
                # and crashed the lifespan handler, so the server refused to boot.
                msg = f"expected a JSON object, got {type(snapshot).__name__}"
                raise ValueError(msg)
            from application.dev.commands import import_state
            result = import_state(snapshot)["data"]
        except (json.JSONDecodeError, OSError, ValueError, TypeError, AttributeError):
            logger.warning("Failed to load %s, will seed fresh", self._path, exc_info=True)
            return False

        # A record written by a different schema version raises inside
        # import_state and is skipped — but clear_all() has already run, so the
        # rows are gone, and the next mutation's debounced save would overwrite
        # the good file and make the loss permanent. Quarantine the snapshot and
        # seed fresh instead of silently serving a hollowed-out store.
        if result["skipped"] or not result["imported"]:
            self._quarantine(result)
            return False

        logger.info("Loaded persisted state from %s", self._path)
        return True

    def _quarantine(self, result: dict) -> None:
        """Move an unusable snapshot aside so the next save cannot destroy it."""
        backup = self._path.with_suffix(self._path.suffix + ".corrupt")
        try:
            os.replace(self._path, backup)
        except OSError:
            logger.error("Could not quarantine %s", self._path, exc_info=True)
        logger.error(
            "Refusing to use %s: imported %d record(s), skipped %d. "
            "Moved to %s and seeding fresh so the snapshot is not overwritten.",
            self._path, result["imported"], result["skipped"], backup,
        )

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
