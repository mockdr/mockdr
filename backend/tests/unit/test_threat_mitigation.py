"""Unit tests for application.threats.mitigation — mitigation, blocklist, fetch, engines."""
import io
import zipfile

import pytest

from application.threats.mitigation import (
    add_to_blacklist,
    disable_engines,
    dv_add_to_blacklist,
    fetch_file,
    mitigate,
)
from infrastructure.seed import generate_all
from repository.activity_repo import activity_repo
from repository.blocklist_repo import blocklist_repo
from repository.threat_repo import threat_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_threat_id() -> str:
    return threat_repo.list_all()[0].id


# ── mitigate ─────────────────────────────────────────────────────────────────


class TestMitigate:
    """Tests for the mitigate command."""

    def test_quarantine_sets_status(self) -> None:
        tid = _first_threat_id()
        result = mitigate("quarantine", [tid])
        assert result["data"]["affected"] == 1
        threat = threat_repo.get(tid)
        assert threat is not None
        assert threat.threatInfo["mitigationStatus"] == "quarantined"

    def test_kill_sets_status(self) -> None:
        tid = _first_threat_id()
        mitigate("kill", [tid])
        threat = threat_repo.get(tid)
        assert threat is not None
        assert threat.threatInfo["mitigationStatus"] == "killed"

    def test_remediate_sets_status(self) -> None:
        tid = _first_threat_id()
        mitigate("remediate", [tid])
        threat = threat_repo.get(tid)
        assert threat is not None
        assert threat.threatInfo["mitigationStatus"] == "remediated"

    def test_rollback_sets_status(self) -> None:
        tid = _first_threat_id()
        mitigate("rollback-remediation", [tid])
        threat = threat_repo.get(tid)
        assert threat is not None
        assert threat.threatInfo["mitigationStatus"] == "rollback"

    def test_un_quarantine_sets_active(self) -> None:
        tid = _first_threat_id()
        mitigate("un-quarantine", [tid])
        threat = threat_repo.get(tid)
        assert threat is not None
        assert threat.threatInfo["mitigationStatus"] == "active"

    def test_unknown_action_raises_400(self) -> None:
        from fastapi import HTTPException
        tid = _first_threat_id()
        with pytest.raises(HTTPException) as exc_info:
            mitigate("not-a-real-action", [tid])
        assert exc_info.value.status_code == 400

    def test_unknown_threat_id_skipped(self) -> None:
        result = mitigate("quarantine", ["does-not-exist"])
        assert result["data"]["affected"] == 0

    def test_multiple_threats(self) -> None:
        ids = [t.id for t in threat_repo.list_all()[:3]]
        result = mitigate("kill", ids)
        assert result["data"]["affected"] == len(ids)
        for tid in ids:
            assert threat_repo.get(tid).threatInfo["mitigationStatus"] == "killed"

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        tid = _first_threat_id()
        mitigate("quarantine", [tid])
        after = len(activity_repo.list_all())
        assert after > before

    def test_updates_timestamp(self) -> None:
        tid = _first_threat_id()
        old_ts = threat_repo.get(tid).threatInfo.get("updatedAt", "")
        mitigate("quarantine", [tid])
        new_ts = threat_repo.get(tid).threatInfo["updatedAt"]
        assert new_ts >= old_ts


# ── add_to_blacklist ─────────────────────────────────────────────────────────


class TestAddToBlacklist:
    """Tests for the add_to_blacklist command."""

    def test_adds_hash_to_blocklist(self) -> None:
        tid = _first_threat_id()
        before = len(blocklist_repo.list_all())
        add_to_blacklist([tid], {})
        after = len(blocklist_repo.list_all())
        assert after == before + 1

    def test_returns_affected_count(self) -> None:
        tid = _first_threat_id()
        result = add_to_blacklist([tid], {})
        assert result["data"]["affected"] == 1

    def test_blocklist_entry_has_correct_type(self) -> None:
        tid = _first_threat_id()
        before_ids = {item.get("id") if isinstance(item, dict) else item.id
                      for item in blocklist_repo.list_all()}
        add_to_blacklist([tid], {})
        for item in blocklist_repo.list_all():
            record = item if isinstance(item, dict) else item.__dict__
            if record.get("id") not in before_ids:
                assert record["type"] == "black_hash"
                assert record["source"] == "threat"
                break

    def test_unknown_id_not_counted(self) -> None:
        result = add_to_blacklist(["fake-id"], {})
        assert result["data"]["affected"] == 0

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        add_to_blacklist([_first_threat_id()], {})
        assert len(activity_repo.list_all()) > before


class TestDvAddToBlacklist:
    """Tests that dv_add_to_blacklist delegates to add_to_blacklist."""

    def test_delegates_correctly(self) -> None:
        tid = _first_threat_id()
        result = dv_add_to_blacklist([tid], {})
        assert result["data"]["affected"] == 1


# ── fetch_file ───────────────────────────────────────────────────────────────


class TestFetchFile:
    """Tests for the fetch_file command."""

    def test_returns_affected_count(self) -> None:
        tid = _first_threat_id()
        result = fetch_file([tid])
        assert result["data"]["affected"] == 1

    def test_stores_zip_on_threat(self) -> None:
        tid = _first_threat_id()
        fetch_file([tid])
        threat = threat_repo.get(tid)
        assert threat is not None
        assert threat._fetched_file is not None
        assert len(threat._fetched_file) > 0

    def test_zip_is_valid(self) -> None:
        tid = _first_threat_id()
        fetch_file([tid])
        threat = threat_repo.get(tid)
        buf = io.BytesIO(threat._fetched_file)
        with zipfile.ZipFile(buf) as zf:
            assert len(zf.namelist()) == 1

    def test_unknown_id_not_counted(self) -> None:
        result = fetch_file(["nonexistent"])
        assert result["data"]["affected"] == 0


# ── disable_engines ──────────────────────────────────────────────────────────


class TestDisableEngines:
    """Tests for the disable_engines command."""

    def test_returns_affected_count(self) -> None:
        tid = _first_threat_id()
        result = disable_engines([tid])
        assert result["data"]["affected"] == 1

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        disable_engines([_first_threat_id()])
        assert len(activity_repo.list_all()) > before

    def test_unknown_id_not_counted(self) -> None:
        result = disable_engines(["nonexistent"])
        assert result["data"]["affected"] == 0
