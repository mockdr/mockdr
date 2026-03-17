"""Integration tests for Sentinel Log Analytics KQL query endpoint."""
from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={"client_id": "sentinel-mock-client-id",
              "client_secret": "sentinel-mock-client-secret",
              "grant_type": "client_credentials"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestKQLQuery:
    """Tests for POST /sentinel/v1/workspaces/{id}/query."""

    def test_query_security_incident(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityIncident | take 5"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "tables" in body
        assert len(body["tables"]) == 1
        table = body["tables"][0]
        assert table["name"] == "PrimaryResult"
        assert "columns" in table
        assert "rows" in table
        assert len(table["rows"]) <= 5

    def test_query_security_alert(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityAlert | take 10"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        assert len(resp.json()["tables"][0]["rows"]) <= 10

    def test_query_with_where_filter(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": 'SecurityIncident | where Severity == "High"'},
            headers=_auth(client),
        )
        assert resp.status_code == 200

    def test_query_with_project(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityIncident | project Title, Severity, Status | take 3"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        table = resp.json()["tables"][0]
        col_names = [c["name"] for c in table["columns"]]
        assert "Title" in col_names
        assert "Severity" in col_names
        assert "Status" in col_names

    def test_query_with_summarize(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityIncident | summarize count() by Severity"},
            headers=_auth(client),
        )
        assert resp.status_code == 200
        table = resp.json()["tables"][0]
        col_names = [c["name"] for c in table["columns"]]
        assert "Severity" in col_names
        assert "count_" in col_names

    def test_query_with_sort(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": "SecurityIncident | sort by IncidentNumber desc | take 5"},
            headers=_auth(client),
        )
        assert resp.status_code == 200

    def test_query_with_where_in(self, client: TestClient) -> None:
        resp = client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            json={"query": 'SecurityIncident | where Severity in ("High", "Medium") | take 10'},
            headers=_auth(client),
        )
        assert resp.status_code == 200
