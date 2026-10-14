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
import time
from pathlib import Path

logger = logging.getLogger(__name__)

#: A save waits until the store has been quiet this long, so a burst of
#: writes is one save rather than one per write.
_DEBOUNCE_SECONDS = 2.0

#: ...but never longer than this after the first unsaved write. A debounce
#: alone restarted with every mutation, and an instance under steady traffic
#: — every request logs itself into the store — never went quiet: a 40 s
#: run of 16 concurrent clients wrote no snapshot at all, so a restart or
#: crash of a busy instance lost everything since it was last idle.
_MAX_DELAY_SECONDS = 30.0


class PersistenceManager:
    """Debounced JSON file persistence for store state.

    One background thread does the saving. A mutation only marks the store
    dirty: the previous design cancelled and started a ``threading.Timer``
    — a new thread — on every single write, which made a reset (some ten
    thousand writes) take a second instead of a tenth of one.
    """

    def __init__(
        self, path: Path,
        debounce: float = _DEBOUNCE_SECONDS, max_delay: float = _MAX_DELAY_SECONDS,
    ) -> None:
        """Initialize persistence with the given JSON file path."""
        self._path = path
        self._debounce = debounce
        self._max_delay = max_delay
        self._cond = threading.Condition()
        self._dirty_since: float | None = None
        self._last_write = 0.0
        self._closed = False
        self._thread: threading.Thread | None = None
        # One save at a time: the background thread and `flush` both save.
        self._save_lock = threading.Lock()

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
            from config import APP_VERSION

            written_by = snapshot.get("_version")
            if written_by != APP_VERSION:
                logger.warning(
                    "%s was written by mockdr %s, this is %s; records whose "
                    "shape changed between the two are skipped below",
                    self._path, written_by or "an unversioned release", APP_VERSION,
                )
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
        """Mark the store dirty; the saver writes it once quiet, or at the latest deadline."""
        with self._cond:
            now = time.monotonic()
            self._last_write = now
            if self._dirty_since is None:
                self._dirty_since = now
            if self._thread is None or not self._thread.is_alive():
                self._closed = False
                self._thread = threading.Thread(
                    target=self._run, name="mockdr-persistence", daemon=True,
                )
                self._thread.start()
            self._cond.notify()

    def _run(self) -> None:
        """Save whenever the store is dirty and the debounce or the deadline has passed."""
        while True:
            with self._cond:
                while self._dirty_since is None and not self._closed:
                    self._cond.wait()
                if self._closed:
                    return
                assert self._dirty_since is not None  # noqa: S101 - loop condition
                due = min(self._last_write + self._debounce, self._dirty_since + self._max_delay)
                remaining = due - time.monotonic()
                if remaining > 0:
                    self._cond.wait(remaining)
                    continue
                self._dirty_since = None
            self._do_save()

    def _do_save(self) -> None:
        """Write the current store state to file atomically."""
        try:
            from application.dev.commands import export_state
            from repository.store import store as _store
            with _store._lock:
                snapshot = export_state()
            dir_path = self._path.parent
            dir_path.mkdir(parents=True, exist_ok=True)
            with self._save_lock:
                fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix=".tmp")
                try:
                    with os.fdopen(fd, "w") as f:
                        json.dump(snapshot, f, default=str)
                        # On disk before the rename: without it a power cut
                        # can leave the renamed file empty on ext4/xfs, the
                        # one failure an atomic replace exists to prevent.
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_path, self._path)
                except BaseException:
                    os.unlink(tmp_path)
                    raise
                _fsync_directory(dir_path)
            logger.debug("Persisted state to %s", self._path)
        except Exception:
            logger.error("Failed to persist state to %s", self._path, exc_info=True)

    def flush(self) -> None:
        """Immediately save (for shutdown) and stop the saver."""
        with self._cond:
            self._closed = True
            self._dirty_since = None
            self._cond.notify()
        self._do_save()


def _fsync_directory(path: Path) -> None:
    """Make a rename in *path* durable; a no-op where directories cannot be opened."""
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


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
