"""Integration tests for POST/DELETE command endpoints.

Verifies that bulk agent actions, threat mitigation commands, and exclusion
CRUD return correct response shapes and affect the expected records.
"""
from fastapi.testclient import TestClient

# ── Agent actions ─────────────────────────────────────────────────────────────

class TestAgentBulkActions:
    """POST /agents/actions/{action} — bulk agent state changes."""

    def _first_agent_id(self, client: TestClient, auth_headers: dict) -> str:
        return client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]["id"]

    def test_requires_auth(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/agents/actions/disconnect",
                           json={"filter": {"ids": ["x"]}})
        assert resp.status_code == 401

    def test_connect_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/agents/actions/connect",
                           headers=auth_headers,
                           json={"filter": {"ids": [agent_id]}})
        assert resp.status_code == 200
        assert "data" in resp.json()
        assert "affected" in resp.json()["data"]

    def test_disconnect_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/agents/actions/disconnect",
                           headers=auth_headers,
                           json={"filter": {"ids": [agent_id]}})
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"]["affected"], int)

    def test_initiate_scan_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/agents/actions/initiate-scan",
                           headers=auth_headers,
                           json={"filter": {"ids": [agent_id]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] >= 1

    def test_decommission_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/agents/actions/decommission",
                           headers=auth_headers,
                           json={"filter": {"ids": [agent_id]}})
        assert resp.status_code == 200
        assert "affected" in resp.json()["data"]

    def test_single_id_filter_affects_exactly_one(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/agents/actions/connect",
                           headers=auth_headers,
                           json={"filter": {"ids": [agent_id]}})
        assert resp.json()["data"]["affected"] == 1


# ── Threat actions ────────────────────────────────────────────────────────────

class TestThreatCommands:
    """Threat mitigation and verdict commands on real S1 URL paths."""

    def _first_threat_id(self, client: TestClient, auth_headers: dict) -> str:
        return client.get("/web/api/v2.1/threats", headers=auth_headers).json()["data"][0]["id"]

    def test_mitigate_remediate_returns_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/threats/mitigate/remediate",
                           headers=auth_headers,
                           json={"filter": {"ids": [tid]}})
        assert resp.status_code == 200
        assert "affected" in resp.json()["data"]

    def test_mitigate_quarantine_returns_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/threats/mitigate/quarantine",
                           headers=auth_headers,
                           json={"filter": {"ids": [tid]}})
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"]["affected"], int)

    def test_add_to_blacklist_returns_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/threats/add-to-blacklist",
                           headers=auth_headers,
                           json={"filter": {"ids": [tid]}})
        assert resp.status_code == 200
        assert "affected" in resp.json()["data"]

    def test_set_analyst_verdict(self, client: TestClient, auth_headers: dict) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/threats/analyst-verdict",
                           headers=auth_headers,
                           json={"filter": {"ids": [tid]}, "data": {"verdict": "true_positive"}})
        assert resp.status_code == 200

    def test_set_incident_status(self, client: TestClient, auth_headers: dict) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/threats/incident",
                           headers=auth_headers,
                           json={"filter": {"ids": [tid]}, "data": {"incidentStatus": "resolved"}})
        assert resp.status_code == 200

    def test_add_note_to_threat(self, client: TestClient, auth_headers: dict) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post(f"/web/api/v2.1/threats/{tid}/notes",
                           headers=auth_headers,
                           json={"text": "Test note from integration test"})
        assert resp.status_code == 200

    def test_fetch_file_stub_returns_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = self._first_threat_id(client, auth_headers)
        resp = client.post("/web/api/v2.1/threats/fetch-file",
                           headers=auth_headers,
                           json={"filter": {"ids": [tid]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_requires_auth(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/threats/mitigate/remediate",
                           json={"filter": {"ids": ["x"]}})
        assert resp.status_code == 401


# ── Exclusion CRUD ────────────────────────────────────────────────────────────

class TestExclusionCommands:
    """POST /exclusions and DELETE /exclusions/{id}."""

    _PAYLOAD = {
        "type": "path",
        "value": "/tmp/test-exclusion",
        "osType": "linux",
        "mode": "suppress",
        "source": "user",
        "userName": "test@example.com",
        "scopeName": "Global",
        "scopePath": "Global",
        "description": "integration test exclusion",
    }

    def test_create_exclusion_returns_created_object(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.post("/web/api/v2.1/exclusions",
                           headers=auth_headers,
                           json=self._PAYLOAD)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert body["data"][0]["value"] == "/tmp/test-exclusion"

    def test_create_exclusion_appears_in_list(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        payload = dict(self._PAYLOAD, value="/tmp/unique-path-xyz")
        client.post("/web/api/v2.1/exclusions", headers=auth_headers, json=payload)
        exclusions = client.get("/web/api/v2.1/exclusions",
                                headers=auth_headers).json()["data"]
        values = [e["value"] for e in exclusions]
        assert "/tmp/unique-path-xyz" in values

    def test_delete_exclusion_removes_it(self, client: TestClient, auth_headers: dict) -> None:
        payload = dict(self._PAYLOAD, value="/tmp/delete-me")
        created = client.post("/web/api/v2.1/exclusions", headers=auth_headers, json=payload)
        eid = created.json()["data"][0]["id"]

        del_resp = client.delete(f"/web/api/v2.1/exclusions/{eid}", headers=auth_headers)
        assert del_resp.status_code == 200

        exclusions = client.get("/web/api/v2.1/exclusions", headers=auth_headers).json()["data"]
        assert all(e["id"] != eid for e in exclusions)

    def test_create_requires_auth(self, client: TestClient) -> None:
        resp = client.post("/web/api/v2.1/exclusions", json=self._PAYLOAD)
        assert resp.status_code == 401
