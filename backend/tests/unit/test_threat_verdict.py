"""Unit tests for application.threats.verdict — verdict and incident status commands."""
import pytest

from application.threats.mitigation import dv_mark_as_threat
from application.threats.verdict import (
    set_analyst_verdict,
    set_incident_status,
)
from infrastructure.seed import generate_all
from repository.activity_repo import activity_repo
from repository.threat_repo import threat_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_threat_id() -> str:
    return threat_repo.list_all()[0].id


# ── set_analyst_verdict ──────────────────────────────────────────────────────


class TestSetAnalystVerdict:
    """Tests for the set_analyst_verdict command."""

    def test_sets_true_positive(self) -> None:
        tid = _first_threat_id()
        result = set_analyst_verdict("true_positive", [tid])
        assert result["data"]["affected"] == 1
        threat = threat_repo.get(tid)
        assert threat.threatInfo["analystVerdict"] == "true_positive"

    def test_sets_false_positive(self) -> None:
        tid = _first_threat_id()
        set_analyst_verdict("false_positive", [tid])
        assert threat_repo.get(tid).threatInfo["analystVerdict"] == "false_positive"

    def test_sets_suspicious(self) -> None:
        tid = _first_threat_id()
        set_analyst_verdict("suspicious", [tid])
        assert threat_repo.get(tid).threatInfo["analystVerdict"] == "suspicious"

    def test_updates_timestamp(self) -> None:
        tid = _first_threat_id()
        old = threat_repo.get(tid).threatInfo.get("updatedAt", "")
        set_analyst_verdict("true_positive", [tid])
        assert threat_repo.get(tid).threatInfo["updatedAt"] >= old

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        set_analyst_verdict("true_positive", [_first_threat_id()])
        assert len(activity_repo.list_all()) > before

    def test_true_positive_creates_activity_type_3784(self) -> None:
        set_analyst_verdict("true_positive", [_first_threat_id()])
        latest = activity_repo.list_all()[0]
        assert latest.activityType == 3784

    def test_false_positive_creates_activity_type_3016(self) -> None:
        set_analyst_verdict("false_positive", [_first_threat_id()])
        latest = activity_repo.list_all()[0]
        assert latest.activityType == 3016

    def test_unknown_id_skipped(self) -> None:
        result = set_analyst_verdict("true_positive", ["nonexistent"])
        assert result["data"]["affected"] == 0

    def test_multiple_threats(self) -> None:
        ids = [t.id for t in threat_repo.list_all()[:3]]
        result = set_analyst_verdict("true_positive", ids)
        assert result["data"]["affected"] == len(ids)


# ── set_incident_status ──────────────────────────────────────────────────────


class TestSetIncidentStatus:
    """Tests for the set_incident_status command."""

    def test_sets_resolved(self) -> None:
        tid = _first_threat_id()
        result = set_incident_status("resolved", [tid])
        assert result["data"]["affected"] == 1
        threat = threat_repo.get(tid)
        assert threat.threatInfo["incidentStatus"] == "resolved"

    def test_sets_in_progress(self) -> None:
        tid = _first_threat_id()
        set_incident_status("in_progress", [tid])
        threat = threat_repo.get(tid)
        assert threat.threatInfo["incidentStatus"] == "in_progress"

    def test_updates_timestamp(self) -> None:
        tid = _first_threat_id()
        old = threat_repo.get(tid).threatInfo.get("updatedAt", "")
        set_incident_status("resolved", [tid])
        assert threat_repo.get(tid).threatInfo["updatedAt"] >= old

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        set_incident_status("resolved", [_first_threat_id()])
        assert len(activity_repo.list_all()) > before

    def test_unknown_id_skipped(self) -> None:
        result = set_incident_status("resolved", ["nonexistent"])
        assert result["data"]["affected"] == 0


# ── the malicious marking, now reached only through Deep Visibility ──────────


class TestDvMarkAsThreat:
    """`dv-mark-as-threat` is published; `mark-as-threat` never was.

    The plain route is gone — `param_drift.py` had it among the routes the
    swagger does not publish — and its body moved behind the one the vendor
    does document, which is the only caller that was left.
    """

    def test_sets_malicious_confidence(self) -> None:
        tid = _first_threat_id()
        result = dv_mark_as_threat([tid])
        assert result["data"]["affected"] == 1
        threat = threat_repo.get(tid)
        assert threat.threatInfo["confidenceLevel"] == "malicious"
        assert threat.threatInfo["analystVerdict"] == "true_positive"

    def test_updates_timestamp(self) -> None:
        tid = _first_threat_id()
        old = threat_repo.get(tid).threatInfo.get("updatedAt", "")
        dv_mark_as_threat([tid])
        assert threat_repo.get(tid).threatInfo["updatedAt"] >= old

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        dv_mark_as_threat([_first_threat_id()])
        assert len(activity_repo.list_all()) > before

    def test_unknown_id_skipped(self) -> None:
        result = dv_mark_as_threat(["nonexistent"])
        assert result["data"]["affected"] == 0


