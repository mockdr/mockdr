"""Behaviours a code review found wrong after they had shipped.

Every one of these returned a `200` carrying something untrue rather than
failing: a finalized search job that went on reporting `QUEUED`, a caller
reported as the `elastic` superuser whoever they were, an import that
confirmed rules it had never created. Each is the failure mode a mock exists
to expose rather than manufacture, so each gets a test that fails loudly if it
comes back.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

SPLUNK_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode(),
}
# `analyst`, not `elastic`: the privileges bug was invisible under a caller
# whose name happens to equal the hardcoded fallback.
ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"analyst:mock-analyst-password").decode(),
    "kbn-xsrf": "true",
}
SPLUNK = "/splunk/services/search/jobs"


@pytest.fixture
def dispatch_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hold every job mid-flight, so the reported state is the derived one."""
    from application.splunk.queries import search as search_queries

    monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 30.0)


def _dispatch(client: TestClient) -> str:
    return str(client.post(
        SPLUNK, data={"search": "search index=sentinelone"},
        headers=SPLUNK_AUTH, params={"output_mode": "json"},
    ).json()["sid"])


def _state(client: TestClient, sid: str) -> tuple[str, str]:
    content = client.get(
        f"{SPLUNK}/{sid}", headers=SPLUNK_AUTH, params={"output_mode": "json"},
    ).json()["entry"][0]["content"]
    return content["dispatchState"], content["isDone"]


def _control(client: TestClient, sid: str, action: str) -> None:
    client.post(f"{SPLUNK}/{sid}/control", data={"action": action}, headers=SPLUNK_AUTH)


class TestDispatchClockRespectsControlActions:
    """The lifecycle clock must not overwrite an explicit instruction."""

    def test_a_job_starts_at_the_beginning(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        assert _state(client, _dispatch(client)) == ("QUEUED", False)

    def test_finalize_sticks(self, client: TestClient, dispatch_window: None) -> None:
        """Deriving state from elapsed time alone made `finalize` a no-op."""
        sid = _dispatch(client)
        _control(client, sid, "finalize")
        assert _state(client, sid) == ("DONE", True)

    def test_cancel_sticks(self, client: TestClient, dispatch_window: None) -> None:
        sid = _dispatch(client)
        _control(client, sid, "cancel")
        assert _state(client, sid) == ("FAILED", True)

    def test_touch_extends_the_ttl_without_rewinding_the_search(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        """`touch` used to reset the dispatch clock, sending a job backwards."""
        sid = _dispatch(client)
        before = _state(client, sid)
        _control(client, sid, "touch")
        assert _state(client, sid) == before

    def test_a_paused_job_is_not_reported_as_done(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        sid = _dispatch(client)
        _control(client, sid, "pause")
        assert _state(client, sid) == ("PAUSED", False)

    def test_pausing_stops_the_clock(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        """A held job must not quietly complete while it is held."""
        import time

        from repository.splunk.search_job_repo import search_job_repo

        sid = _dispatch(client)
        _control(client, sid, "pause")
        job = search_job_repo.get(sid)
        assert job is not None

        # Simulate a job dispatched a minute ago that was paused two seconds
        # in. An unpaused job that old would be long past the 30s window.
        job.published_at = time.time() - 60.0
        job.paused_at = job.published_at + 2.0
        search_job_repo.save(job)
        assert _state(client, sid) == ("PAUSED", False)

        _control(client, sid, "unpause")
        # Resumes two seconds in, where it stopped — not at the end.
        assert _state(client, sid) == ("QUEUED", False)


class TestKibanaReportsTheTruth:
    """Routes that answered `200` with something that was not so."""

    def test_privileges_name_the_actual_caller(self, client: TestClient) -> None:
        """The auth context spells it `user`; reading `username` always missed."""
        body = client.get("/kibana/api/detection_engine/privileges", headers=ES_AUTH).json()
        assert body["username"] == "analyst"

    def test_bulk_create_accepts_a_risk_score_of_zero(self, client: TestClient) -> None:
        """`not entry.get(f)` rejected a supplied 0 as `"undefined"`."""
        body = client.post(
            "/kibana/api/detection_engine/rules/_bulk_create", headers=ES_AUTH,
            json=[{
                "name": "Zero risk", "description": "d", "type": "query",
                "severity": "low", "risk_score": 0, "rule_id": "zero-risk-rule",
            }],
        ).json()
        assert "error" not in body[0], body[0]
        assert body[0]["risk_score"] == 0

    def test_bulk_create_still_rejects_an_absent_field(self, client: TestClient) -> None:
        body = client.post(
            "/kibana/api/detection_engine/rules/_bulk_create", headers=ES_AUTH,
            json=[{"name": "No severity", "description": "d", "type": "query"}],
        ).json()
        assert body[0]["error"]["status_code"] == 400

    def test_an_unknown_space_is_a_404(self, client: TestClient) -> None:
        """Falling back to the default space confirmed ids that do not exist."""
        resp = client.get("/kibana/api/spaces/space/no-such-space", headers=ES_AUTH)
        assert resp.status_code == 404

    def test_the_default_space_is_still_served(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/spaces/space/default", headers=ES_AUTH)
        assert resp.status_code == 200
        assert resp.json()["id"] == "default"

    def test_an_exception_summary_needs_a_list_to_summarise(
        self, client: TestClient,
    ) -> None:
        """All-zero counts were indistinguishable from an empty list."""
        assert client.get(
            "/kibana/api/exception_lists/summary", headers=ES_AUTH,
        ).status_code == 400


class TestEndpointActions:
    """What is pending, and in what order it happened."""

    @staticmethod
    def _agent(client: TestClient) -> str:
        listing = client.get("/kibana/api/endpoint/metadata", headers=ES_AUTH).json()
        return str(listing["data"][0]["metadata"]["agent"]["id"])

    def test_pending_actions_name_the_action(self, client: TestClient) -> None:
        """Everything pending was filed under `isolate`, whatever it was."""
        agent = self._agent(client)
        client.post(
            "/kibana/api/endpoint/kill_process", headers=ES_AUTH,
            json={"endpoint_ids": [agent], "parameters": {"pid": 42}},
        )
        pending = client.get(
            "/kibana/api/endpoint/action_status", headers=ES_AUTH,
            params={"agent_ids": agent},
        ).json()["data"][0]["pending_actions"]
        assert pending.get("kill-process") == 1, pending
        assert "isolate" not in pending

    def test_the_action_log_is_newest_first(self, client: TestClient) -> None:
        """It documented newest-first and served repository insertion order."""
        agent = self._agent(client)
        for comment in ("older", "newer"):
            client.post(
                "/kibana/api/endpoint/isolate", headers=ES_AUTH,
                json={"endpoint_ids": [agent], "comment": comment},
            )
        entries = client.get(
            f"/kibana/api/endpoint/action_log/{agent}", headers=ES_AUTH,
        ).json()["data"]
        stamps = [e["started_at"] for e in entries]
        assert len(stamps) >= 2
        assert stamps == sorted(stamps, reverse=True)


class TestRuleImportActuallyImports:
    """`_import` read no body and reported success for zero rules."""

    @staticmethod
    def _export(client: TestClient) -> str:
        return client.post(
            "/kibana/api/detection_engine/rules/_export", headers=ES_AUTH, json={},
        ).text

    @staticmethod
    def _count(client: TestClient) -> int:
        return int(client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"per_page": 1},
        ).json()["total"])

    def test_a_new_rule_is_created(self, client: TestClient) -> None:
        before = self._count(client)
        payload = json.dumps({
            "rule_id": "brand-new-imported", "name": "New", "description": "d",
            "type": "query", "severity": "low", "risk_score": 10,
        })
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            content=payload.encode(),
        ).json()
        assert body["success"] is True
        assert body["success_count"] == 1
        assert self._count(client) == before + 1

    def test_re_importing_an_export_reports_conflicts(self, client: TestClient) -> None:
        """Silence here made a failed migration look like a successful one."""
        ndjson = self._export(client)
        rules = len([line for line in ndjson.splitlines() if line.strip()]) - 1
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            content=ndjson.encode(),
        ).json()
        assert body["rules_count"] == rules
        assert body["success_count"] == 0
        assert body["success"] is False
        assert len(body["errors"]) == rules
        assert body["errors"][0]["error"]["status_code"] == 409

    def test_overwrite_replaces_them(self, client: TestClient) -> None:
        ndjson = self._export(client)
        rules = len([line for line in ndjson.splitlines() if line.strip()]) - 1
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            params={"overwrite": "true"}, content=ndjson.encode(),
        ).json()
        assert body["success"] is True
        assert body["success_count"] == rules

    def test_the_export_summary_line_is_not_counted_as_a_rule(
        self, client: TestClient,
    ) -> None:
        ndjson = self._export(client)
        summary = json.loads(ndjson.strip().splitlines()[-1])
        assert "exported_count" in summary
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            params={"overwrite": "true"}, content=ndjson.encode(),
        ).json()
        assert body["rules_count"] == summary["exported_count"]

    def test_a_multipart_upload_works_too(self, client: TestClient) -> None:
        """Kibana's own UI posts the file as multipart, not as a raw body."""
        before = self._count(client)
        payload = json.dumps({
            "rule_id": "multipart-imported", "name": "Multipart", "description": "d",
            "type": "query", "severity": "low", "risk_score": 10,
        })
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            files={"file": ("rules.ndjson", payload, "application/ndjson")},
        ).json()
        assert body["success_count"] == 1
        assert self._count(client) == before + 1

    def test_a_malformed_line_is_reported_not_swallowed(
        self, client: TestClient,
    ) -> None:
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            content=b"{not json at all\n",
        ).json()
        assert body["success"] is False
        assert body["errors"][0]["error"]["status_code"] == 400
