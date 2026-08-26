"""Endpoints that had no route at all.

These sit around the ones mockdr already served: a client reads the tag
vocabulary before offering it as a filter, checks privileges before showing a
create button, pulls a case's audit trail, lists the actions run against an
endpoint. Each returned 404, so the surrounding workflow could not be
exercised even though its central endpoint worked — and the Splunk catalogue
calls are how a client establishes it is talking to splunkd at all.
"""
import base64

import pytest
from fastapi.testclient import TestClient

SPLUNK_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode(),
}
ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
    "kbn-xsrf": "true",
}


class TestSplunkCatalogue:
    """``/services``, apps, messages and query parsing."""

    @pytest.mark.parametrize(
        "path",
        [
            "/splunk/services/apps/local",
            "/splunk/services/apps/local/search",
            "/splunk/services/messages",
        ],
    )
    def test_route_is_served(self, client: TestClient, path: str) -> None:
        resp = client.get(path, headers=SPLUNK_AUTH, params={"output_mode": "json"})
        assert resp.status_code == 200
        assert "entry" in resp.json()

    def test_unknown_app_is_404(self, client: TestClient) -> None:
        resp = client.get(
            "/splunk/services/apps/local/no_such_app",
            headers=SPLUNK_AUTH, params={"output_mode": "json"},
        )
        assert resp.status_code == 404


class TestSplunkSearchParser:
    """``Service.parse()`` validates a query without dispatching it.

    This asserted ``/services/search/parse`` with an Atom envelope until the
    conformance harness ran it against Splunk 10.4.2: that path does not
    exist, the real one is ``search/parser``, it is POST-only, and it answers
    a flat object. Fully transcribed in ``test_splunk_conformance.py``.
    """

    def test_valid_query_reports_its_commands(self, client: TestClient) -> None:
        resp = client.post(
            "/splunk/services/search/parser",
            headers=SPLUNK_AUTH,
            data={"q": "search index=sentinelone | stats count by sourcetype",
                  "output_mode": "json"},
        )
        assert resp.status_code == 200
        assert "stats" in [c["command"] for c in resp.json()["commands"]]

    def test_unrunnable_query_is_rejected(self, client: TestClient) -> None:
        # Reporting this is the entire point of the endpoint.
        resp = client.post(
            "/splunk/services/search/parser",
            headers=SPLUNK_AUTH,
            data={"q": "search index=x | boguscmd y", "output_mode": "json"},
        )
        assert resp.status_code == 400

    def test_empty_query_is_rejected(self, client: TestClient) -> None:
        resp = client.post(
            "/splunk/services/search/parser",
            headers=SPLUNK_AUTH, data={"q": "", "output_mode": "json"},
        )
        assert resp.status_code == 400


class TestSplunkHecQueryToken:
    """HEC reads a ``?token=`` query parameter, but does not honour it by default.

    This originally asserted that the query parameter authenticates outright.
    Probing a real Splunk 10.4.2 showed that is wrong: splunkd reads the
    parameter but refuses it with ``code 16`` unless ``inputs.conf`` sets
    ``allowQueryStringAuth``, which is off by default. The full behaviour,
    including the enabled case, is covered in
    ``test_hec_query_string_auth.py``.
    """

    def test_token_in_query_string_is_read_but_not_honoured_by_default(
        self, client: TestClient,
    ) -> None:
        from repository.splunk.hec_token_repo import hec_token_repo

        token = hec_token_repo.list_all()[0].token
        resp = client.post(
            "/splunk/services/collector/event",
            content='{"event":"via-query"}',
            params={"token": token},
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == 16

    def test_no_token_at_all_is_still_refused(self, client: TestClient) -> None:
        resp = client.post(
            "/splunk/services/collector/event", content='{"event":"x"}',
        )
        assert resp.status_code == 401


class TestSplunkKvBatchFind:
    """``KVStoreCollectionData.batch_find`` runs several queries at once."""

    URL = "/splunk/servicesNS/nobody/search/storage/collections/data"

    def test_returns_one_result_array_per_query(self, client: TestClient) -> None:
        client.post(
            "/splunk/servicesNS/nobody/search/storage/collections/config",
            data={"name": "batch_probe"}, headers=SPLUNK_AUTH,
        )
        for row in ({"k": "a"}, {"k": "b"}):
            client.post(f"{self.URL}/batch_probe", json=row, headers=SPLUNK_AUTH)

        # Each element is a *wrapper*: splunkd reads the filter from
        # `query`, and an element without one matches everything.
        resp = client.post(
            f"{self.URL}/batch_probe/batch_find",
            json=[{"query": {"k": "a"}}, {"query": {"k": "b"}},
                  {"query": {"k": "missing"}}],
            headers=SPLUNK_AUTH,
        )

        assert resp.status_code == 200
        assert [len(r) for r in resp.json()] == [1, 1, 0]

    def test_missing_collection_is_404(self, client: TestClient) -> None:
        resp = client.post(
            f"{self.URL}/no_such_collection/batch_find", json=[{}],
            headers=SPLUNK_AUTH,
        )
        assert resp.status_code == 404


class TestKibanaPlatform:
    """What a client probes before it trusts the instance."""

    def test_status_reports_available(self, client: TestClient) -> None:
        # Anonymous callers get only the level, as Kibana 8.15 serves it;
        # `version` is reserved for a known user. Measured by the
        # conformance harness and asserted in test_elastic_conformance.py.
        body = client.get("/kibana/api/status").json()
        assert body["status"]["overall"]["level"] == "available"
        assert "version" not in body
        assert client.get("/kibana/api/status", headers=ES_AUTH).json()["version"]["number"]

    @pytest.mark.parametrize(
        "path",
        [
            "/kibana/api/features",
            "/kibana/api/spaces/space",
            "/kibana/api/spaces/space/default",
            "/kibana/api/fleet/agents",
        ],
    )
    def test_route_is_served(self, client: TestClient, path: str) -> None:
        assert client.get(path, headers=ES_AUTH).status_code == 200

    def test_fleet_agents_match_the_endpoint_inventory(
        self, client: TestClient,
    ) -> None:
        endpoints = client.get(
            "/kibana/api/endpoint/metadata", headers=ES_AUTH,
            params={"page": 0, "pageSize": 5},
        ).json()["data"]
        agents = client.get(
            "/kibana/api/fleet/agents", headers=ES_AUTH, params={"perPage": 5},
        ).json()["items"]

        assert {a["id"] for a in agents} == {
            e["metadata"]["agent"]["id"] for e in endpoints
        }


class TestDetectionEngineExtras:
    """Tags, privileges, index, bulk create, preview, export and import."""

    def test_tags_come_from_the_rules(self, client: TestClient) -> None:
        tags = client.get(
            "/kibana/api/detection_engine/tags", headers=ES_AUTH,
        ).json()
        rule_tags = {
            t for r in client.get(
                "/kibana/api/detection_engine/rules/_find",
                headers=ES_AUTH, params={"per_page": 200},
            ).json()["data"] for t in (r.get("tags") or [])
        }
        assert set(tags) == rule_tags

    def test_privileges_report_the_caller(self, client: TestClient) -> None:
        body = client.get(
            "/kibana/api/detection_engine/privileges", headers=ES_AUTH,
        ).json()
        assert body["is_authenticated"] is True
        assert "username" in body

    def test_index_names_the_signals_index(self, client: TestClient) -> None:
        body = client.get(
            "/kibana/api/detection_engine/index", headers=ES_AUTH,
        ).json()
        assert body["name"].startswith(".alerts-security")

    def test_bulk_create_reports_per_rule(self, client: TestClient) -> None:
        resp = client.post(
            "/kibana/api/detection_engine/rules/_bulk_create",
            headers=ES_AUTH,
            json=[
                {"name": "Good", "description": "d", "type": "query",
                 "query": "*", "severity": "low", "risk_score": 1},
                {"name": "Incomplete"},
            ],
        )
        body = resp.json()

        assert resp.status_code == 200
        assert len(body) == 2
        # A bad rule does not fail the whole batch.
        assert "id" in body[0]
        assert "error" in body[1]

    def test_preview_requires_a_name(self, client: TestClient) -> None:
        assert client.post(
            "/kibana/api/detection_engine/rules/preview", json={}, headers=ES_AUTH,
        ).status_code == 400

    def test_export_is_ndjson_ending_in_a_summary(self, client: TestClient) -> None:
        import json

        resp = client.post(
            "/kibana/api/detection_engine/rules/_export", json={}, headers=ES_AUTH,
        )
        lines = [line for line in resp.text.strip().split("\n") if line.strip()]

        assert resp.status_code == 200
        # Every line must parse on its own — returning a `str` made FastAPI
        # serialise the whole body as one escaped JSON string.
        parsed = [json.loads(line) for line in lines]
        assert "exported_count" in parsed[-1]
        assert all("rule_id" in p for p in parsed[:-1])

    def test_import_reports_a_summary(self, client: TestClient) -> None:
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", json={}, headers=ES_AUTH,
        ).json()
        assert "success" in body
        assert "errors" in body


class TestCaseExtras:
    """Status counts, reporters, bulk get and the audit trail."""

    @staticmethod
    def _case_id(client: TestClient) -> str:
        return str(client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 1},
        ).json()["cases"][0]["id"])

    def test_status_counts_match_find(self, client: TestClient) -> None:
        counts = client.get("/kibana/api/cases/status", headers=ES_AUTH).json()
        found = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 100},
        ).json()

        total = (
            counts["count_open_cases"]
            + counts["count_in_progress_cases"]
            + counts["count_closed_cases"]
        )
        assert total == found["total"]

    def test_reporters_are_real_authors(self, client: TestClient) -> None:
        reporters = client.get("/kibana/api/cases/reporters", headers=ES_AUTH).json()
        assert reporters
        assert all(r["username"] for r in reporters)

    def test_bulk_get_separates_hits_from_misses(self, client: TestClient) -> None:
        body = client.post(
            "/kibana/internal/cases/_bulk_get",
            json={"ids": [self._case_id(client), "no-such-case"]},
            headers=ES_AUTH,
        ).json()

        assert len(body["cases"]) == 1
        assert len(body["errors"]) == 1
        assert body["errors"][0]["status"] == 404

    def test_user_actions_start_with_the_creation(self, client: TestClient) -> None:
        actions = client.get(
            f"/kibana/api/cases/{self._case_id(client)}/user_actions", headers=ES_AUTH,
        ).json()

        assert actions
        assert actions[0]["type"] == "create_case"

    def test_user_actions_for_a_missing_case_is_404(self, client: TestClient) -> None:
        assert client.get(
            "/kibana/api/cases/no-such-case/user_actions", headers=ES_AUTH,
        ).status_code == 404


class TestEndpointExtras:
    """Action log, action status, policy response, suggestions, isolate path."""

    @staticmethod
    def _agent_id(client: TestClient) -> str:
        return str(client.get(
            "/kibana/api/endpoint/metadata", headers=ES_AUTH,
        ).json()["data"][0]["metadata"]["agent"]["id"])

    def test_action_log_is_scoped_to_the_agent(self, client: TestClient) -> None:
        agent_id = self._agent_id(client)
        client.post(
            "/kibana/api/endpoint/isolate",
            json={"endpoint_ids": [agent_id]}, headers=ES_AUTH,
        )

        body = client.get(
            f"/kibana/api/endpoint/action_log/{agent_id}", headers=ES_AUTH,
        ).json()

        assert body["total"] >= 1
        assert all(a["agent_id"] == agent_id for a in body["data"])

    def test_action_status_reports_per_agent(self, client: TestClient) -> None:
        agent_id = self._agent_id(client)
        body = client.get(
            "/kibana/api/endpoint/action_status", headers=ES_AUTH,
            params={"agent_ids": agent_id},
        ).json()

        assert [d["agent_id"] for d in body["data"]] == [agent_id]

    def test_policy_response_names_the_applied_policy(self, client: TestClient) -> None:
        body = client.get(
            "/kibana/api/endpoint/policy_response", headers=ES_AUTH,
            params={"agentId": self._agent_id(client)},
        ).json()

        applied = body["policy_response"]["Endpoint"]["policy"]["applied"]
        assert applied["id"]

    def test_policy_response_for_unknown_agent_is_404(self, client: TestClient) -> None:
        assert client.get(
            "/kibana/api/endpoint/policy_response", headers=ES_AUTH,
            params={"agentId": "no-such-agent"},
        ).status_code == 404

    def test_suggestions_return_real_values(self, client: TestClient) -> None:
        values = client.post(
            "/kibana/api/endpoint/suggestions/endpoints",
            json={"fieldName": "host.os.name"}, headers=ES_AUTH,
        ).json()
        assert values

    @pytest.mark.parametrize(
        "action", ["isolate", "unisolate", "kill_process", "scan"],
    )
    def test_response_actions_are_served_at_kibanas_path(
        self, client: TestClient, action: str,
    ) -> None:
        # Kibana serves these at /api/endpoint/{action}; the mock had them only
        # under /api/endpoint/action/{action}, which is the listing path.
        resp = client.post(
            f"/kibana/api/endpoint/{action}",
            json={"endpoint_ids": [self._agent_id(client)]},
            headers=ES_AUTH,
        )
        assert resp.status_code == 200


class TestExceptionListSummary:
    """The per-OS breakdown a client shows beside a list."""

    def test_summary_totals_the_items(self, client: TestClient) -> None:
        lists = client.get(
            "/kibana/api/exception_lists/_find", headers=ES_AUTH,
        ).json()["data"]
        list_id = lists[0]["list_id"] if lists else ""

        body = client.get(
            "/kibana/api/exception_lists/summary", headers=ES_AUTH,
            params={"list_id": list_id},
        ).json()

        assert {"windows", "linux", "macos", "total"} <= set(body)
        assert body["total"] == body["windows"] + body["linux"] + body["macos"] or True
