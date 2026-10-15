"""MOCKDR_PERSIST on an instance that is busy, crashes, and gets upgraded.

* Saves were debounced by restarting a timer on every mutation. Every
  request logs itself into the store, so under steady traffic the store
  never went quiet and nothing was written: 16 concurrent clients for 40 s
  left no snapshot at all, and a crash lost everything since the last idle
  moment. A save now happens at the latest ``max_delay`` after the first
  unsaved write.
* Each mutation started (and cancelled) a ``threading.Timer`` — a thread
  per store write; a reset took a second instead of a tenth of one.
* The atomic replace was not durable: no fsync before the rename.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

from infrastructure.persistence import PersistenceManager


def test_a_busy_store_is_still_saved(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    manager = PersistenceManager(path, debounce=0.2, max_delay=0.4)
    try:
        # Generous on purpose: a save serialises the whole seeded store, and
        # on a loaded machine (ci.sh beside a soak run) that alone took more
        # than the 1.5 s this allowed. The loop leaves as soon as the file
        # exists; only a store that is never saved — the defect — waits it out.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not path.exists():
            manager.schedule_save()  # never quiet for the 0.2 s debounce
            time.sleep(0.02)
        assert path.exists(), "a store that never went quiet was never saved"
    finally:
        manager.flush()


def test_a_quiet_store_is_saved_once_after_the_debounce(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    manager = PersistenceManager(path, debounce=0.05, max_delay=5)
    try:
        for _ in range(50):
            manager.schedule_save()
        deadline = time.monotonic() + 2
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert path.exists()
        assert json.loads(path.read_text())["_version"]
    finally:
        manager.flush()


def test_a_write_does_not_cost_a_thread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[str] = []
    original = threading.Thread.start

    def counting_start(self: threading.Thread) -> None:
        started.append(self.name)
        original(self)

    monkeypatch.setattr(threading.Thread, "start", counting_start)
    manager = PersistenceManager(tmp_path / "state.json", debounce=10, max_delay=10)
    try:
        for _ in range(1000):
            manager.schedule_save()
    finally:
        manager.flush()
    assert len(started) <= 1, f"{len(started)} threads for 1000 writes"


def test_the_snapshot_is_on_disk_before_it_replaces_the_old_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    synced: list[int] = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real_fsync(fd))[1])

    PersistenceManager(tmp_path / "state.json").flush()

    assert synced, "the snapshot was renamed into place without an fsync"
