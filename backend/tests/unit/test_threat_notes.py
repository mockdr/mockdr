"""Unit tests for application.threats.notes — analyst note commands."""
import pytest

from application.threats.notes import add_note, bulk_add_notes
from infrastructure.seed import generate_all
from repository.threat_repo import threat_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_threat_id() -> str:
    return threat_repo.list_all()[0].id


# ── add_note ─────────────────────────────────────────────────────────────────


class TestAddNote:
    """Tests for the add_note command."""

    def test_returns_note_data(self) -> None:
        tid = _first_threat_id()
        result = add_note(tid, "Test note", "user-123")
        assert result is not None
        assert "data" in result
        assert result["data"]["text"] == "Test note"

    def test_note_has_id(self) -> None:
        result = add_note(_first_threat_id(), "Note", "u1")
        assert result["data"]["id"]

    def test_note_has_timestamp(self) -> None:
        result = add_note(_first_threat_id(), "Note", "u1")
        assert result["data"]["createdAt"]

    def test_note_has_user_id(self) -> None:
        result = add_note(_first_threat_id(), "Note", "user-abc")
        assert result["data"]["userId"] == "user-abc"

    def test_appends_to_threat_notes(self) -> None:
        tid = _first_threat_id()
        before = len(threat_repo.get(tid).notes)
        add_note(tid, "Appended", "u1")
        after = len(threat_repo.get(tid).notes)
        assert after == before + 1

    def test_multiple_notes_accumulate(self) -> None:
        tid = _first_threat_id()
        before = len(threat_repo.get(tid).notes)
        add_note(tid, "First", "u1")
        add_note(tid, "Second", "u1")
        assert len(threat_repo.get(tid).notes) == before + 2

    def test_unknown_threat_returns_none(self) -> None:
        result = add_note("nonexistent", "Note", "u1")
        assert result is None

    def test_none_user_id_accepted(self) -> None:
        result = add_note(_first_threat_id(), "Note", None)
        assert result is not None
        assert result["data"]["userId"] is None


# ── bulk_add_notes ───────────────────────────────────────────────────────────


class TestBulkAddNotes:
    """Tests for the bulk_add_notes command."""

    def test_returns_affected_count(self) -> None:
        ids = [t.id for t in threat_repo.list_all()[:3]]
        result = bulk_add_notes(ids, "Bulk note")
        assert result["data"]["affected"] == len(ids)

    def test_all_threats_get_the_note(self) -> None:
        ids = [t.id for t in threat_repo.list_all()[:2]]
        bulk_add_notes(ids, "SOC review", "u1")
        for tid in ids:
            texts = [n["text"] for n in threat_repo.get(tid).notes]
            assert "SOC review" in texts

    def test_unknown_ids_not_counted(self) -> None:
        result = bulk_add_notes(["fake1", "fake2"], "Note")
        assert result["data"]["affected"] == 0

    def test_mixed_valid_and_invalid(self) -> None:
        valid_id = _first_threat_id()
        result = bulk_add_notes([valid_id, "fake"], "Mixed note")
        assert result["data"]["affected"] == 1

    def test_empty_list(self) -> None:
        result = bulk_add_notes([], "Note")
        assert result["data"]["affected"] == 0
