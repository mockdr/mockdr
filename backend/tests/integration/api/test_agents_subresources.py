"""Integration tests for agent sub-resource endpoints.

Covers /agents/processes?ids=, /agents/applications?ids=, and the count
endpoint. These routes exercise agent query methods not covered elsewhere.
"""
from fastapi.testclient import TestClient


class TestAgentProcesses:
    def _first_agent_id(self, client: TestClient, auth_headers: dict) -> str:
        return client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]["id"]

    def test_requires_auth(self, client: TestClient) -> None:
        agents = client.get("/web/api/v2.1/agents",
                            headers={"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
                            ).json()["data"]
        agent_id = agents[0]["id"]
        resp = client.get(f"/web/api/v2.1/agents/processes?ids={agent_id}")
        assert resp.status_code == 401

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.get(f"/web/api/v2.1/agents/processes?ids={agent_id}", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        # AgentProcessesSchema_many: data and errors, no pagination block
        assert "pagination" not in body
        assert isinstance(body["data"], list)

    def test_processes_have_required_fields(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        processes = client.get(f"/web/api/v2.1/agents/processes?ids={agent_id}",
                               headers=auth_headers).json()["data"]
        if processes:
            proc = processes[0]
            for field in ("pid", "processName", "executablePath"):
                assert field in proc, f"Required field '{field}' missing from process"


class TestAgentApplications:
    def _first_agent_id(self, client: TestClient, auth_headers: dict) -> str:
        return client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]["id"]

    def test_returns_data_and_pagination(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        resp = client.get(f"/web/api/v2.1/agents/applications?ids={agent_id}", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_applications_have_required_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_id = self._first_agent_id(client, auth_headers)
        apps = client.get(f"/web/api/v2.1/agents/applications?ids={agent_id}",
                          headers=auth_headers).json()["data"]
        if apps:
            app = apps[0]
            for field in ('name', 'version', 'publisher'):  # AgentApplicationsSchema (2.1 swagger)
                assert field in app, f"Required field '{field}' missing from application"


class TestAgentPassphrase:
    def test_returns_passphrase(self, client: TestClient, auth_headers: dict) -> None:
        agent_id = client.get("/web/api/v2.1/agents",
                              headers=auth_headers).json()["data"][0]["id"]
        resp = client.get(f"/web/api/v2.1/agents/passphrases?ids={agent_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert "passphrase" in resp.json()["data"][0]
        assert len(resp.json()["data"][0]["passphrase"]) > 0


class TestAgentListFilters:
    """Exercise additional filter code paths in agent queries."""

    def test_filter_by_infected_true(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers,
                          params={"infected": "true"})
        assert resp.status_code == 200
        for agent in resp.json()["data"]:
            assert agent["infected"] is True

    def test_filter_by_is_active_true(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers,
                          params={"isActive": "true"})
        assert resp.status_code == 200
        for agent in resp.json()["data"]:
            assert agent["isActive"] is True

    def test_filter_by_network_status(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers,
                          params={"networkStatuses": "connected"})
        assert resp.status_code == 200
        for agent in resp.json()["data"]:
            assert agent["networkStatus"] == "connected"

    def test_filter_by_computer_name(self, client: TestClient, auth_headers: dict) -> None:
        agents = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"]
        name_prefix = agents[0]["computerName"][:3]
        resp = client.get("/web/api/v2.1/agents", headers=auth_headers,
                          params={"computerName": name_prefix})
        assert resp.status_code == 200

    def test_passphrases_endpoint_returns_list(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get("/web/api/v2.1/agents/passphrases", headers=auth_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_tags_endpoint_returns_list(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/agents/tags", headers=auth_headers)
        assert resp.status_code == 200
