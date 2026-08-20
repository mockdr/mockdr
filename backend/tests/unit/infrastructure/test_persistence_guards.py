"""Snapshot-loading safety regressions.

A snapshot written by a different schema version used to load "successfully"
with every affected record silently dropped. Because ``import_state`` clears
the store first and saves are debounced, the next mutation then overwrote the
good file — turning a recoverable version mismatch into permanent data loss.
"""
import json
from pathlib import Path

import pytest

from application.dev.commands import export_state
from infrastructure import seed
from infrastructure.persistence import PersistenceManager


@pytest.fixture
def snapshot() -> dict:
    """A complete, valid snapshot of freshly seeded state."""
    seed.generate_all()
    return export_state()


def _write(tmp_path: Path, name: str, payload: object) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(payload, default=str))
    return path


class TestLossySnapshotsAreRefused:
    """A snapshot that cannot be fully restored must not be adopted."""

    def test_schema_drift_is_refused_rather_than_partially_loaded(
        self, tmp_path: Path, snapshot: dict,
    ) -> None:
        for record in snapshot["agents"]:
            record["field_from_a_future_version"] = 1
        path = _write(tmp_path, "drifted", snapshot)

        assert PersistenceManager(path).load_if_exists() is False

    def test_refused_snapshot_is_quarantined_not_left_to_be_overwritten(
        self, tmp_path: Path, snapshot: dict,
    ) -> None:
        for record in snapshot["agents"]:
            record["field_from_a_future_version"] = 1
        path = _write(tmp_path, "drifted", snapshot)

        PersistenceManager(path).load_if_exists()

        quarantined = path.with_suffix(path.suffix + ".corrupt")
        assert quarantined.exists(), "the only copy of the data must survive"
        assert not path.exists(), "the live path must be free for a fresh save"
        assert json.loads(quarantined.read_text())["agents"], "contents preserved"

    def test_empty_object_snapshot_is_refused(self, tmp_path: Path) -> None:
        # Valid JSON, imports cleanly, restores nothing — previously left the
        # store permanently empty and reported success.
        path = _write(tmp_path, "empty", {})
        assert PersistenceManager(path).load_if_exists() is False


class TestMalformedSnapshotsDoNotCrashStartup:
    """A bad file makes the server seed fresh; it must never refuse to boot."""

    @pytest.mark.parametrize("payload", [[], None, "a string", 42])
    def test_non_object_snapshot_returns_false(
        self, tmp_path: Path, payload: object,
    ) -> None:
        path = _write(tmp_path, "not-an-object", payload)
        assert PersistenceManager(path).load_if_exists() is False

    def test_truncated_json_returns_false(self, tmp_path: Path) -> None:
        path = tmp_path / "truncated.json"
        path.write_text('{"agents": [{"id": "1"')
        assert PersistenceManager(path).load_if_exists() is False

    def test_missing_file_returns_false(self, tmp_path: Path) -> None:
        assert PersistenceManager(tmp_path / "absent.json").load_if_exists() is False


class TestValidSnapshotStillLoads:
    """The guard must not reject good snapshots."""

    def test_round_trip_loads_and_is_not_quarantined(
        self, tmp_path: Path, snapshot: dict,
    ) -> None:
        path = _write(tmp_path, "good", snapshot)

        assert PersistenceManager(path).load_if_exists() is True
        assert path.exists()
        assert not path.with_suffix(path.suffix + ".corrupt").exists()
