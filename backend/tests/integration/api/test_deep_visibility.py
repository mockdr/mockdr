"""Integration tests for Deep Visibility endpoints.

POST /dv/init-query          — create a new query
GET  /dv/query-status        — poll status
GET  /dv/events              — fetch events
GET  /dv/events/{event_type} — fetch events filtered by type
POST /dv/cancel-query        — cancel a query
"""
from fastapi.testclient import TestClient

from repository.agent_repo import agent_repo

BASE = "/web/api/v2.1"


def _init_query(client: TestClient, auth_headers: dict) -> str:
    """Create a query and return the queryId."""
    resp = client.post(
        f"{BASE}/dv/init-query",
        headers=auth_headers,
        json={
            "query": "EventType = 'Process Creation'",
            "fromDate": "2024-01-01T00:00:00Z",
            "toDate": "2024-12-31T23:59:59Z",
        },
    )
    assert resp.status_code == 200
    return resp.json()["data"]["queryId"]


class TestInitQuery:
    def test_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/dv/init-query",
            headers=auth_headers,
            json={
                "query": "EventType = 'File Creation'",
                "fromDate": "2024-01-01T00:00:00Z",
                "toDate": "2024-12-31T23:59:59Z",
            },
        )
        assert resp.status_code == 200

    def test_returns_query_id(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/dv/init-query",
            headers=auth_headers,
            json={
                "query": "EventType = 'Network Action'",
                "fromDate": "2024-01-01T00:00:00Z",
                "toDate": "2024-12-31T23:59:59Z",
            },
        )
        body = resp.json()
        assert "data" in body
        assert "queryId" in body["data"]

    def test_requires_auth(self, client: TestClient) -> None:
        resp = client.post(
            f"{BASE}/dv/init-query",
            json={"query": "test", "fromDate": "2024-01-01T00:00:00Z", "toDate": "2024-12-31T23:59:59Z"},
        )
        assert resp.status_code == 401


class TestQueryStatus:
    def test_returns_200_for_known_query(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        resp = client.get(f"{BASE}/dv/query-status", headers=auth_headers, params={"queryId": qid})
        assert resp.status_code == 200

    def test_returns_status_field(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        body = client.get(
            f"{BASE}/dv/query-status", headers=auth_headers, params={"queryId": qid}
        ).json()
        assert "data" in body

    def test_unknown_query_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(
            f"{BASE}/dv/query-status", headers=auth_headers, params={"queryId": "nonexistent-id"}
        )
        assert resp.status_code == 404


class TestGetEvents:
    def test_returns_200_for_known_query(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        resp = client.get(f"{BASE}/dv/events", headers=auth_headers, params={"queryId": qid})
        assert resp.status_code == 200

    def test_returns_data_list(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        body = client.get(
            f"{BASE}/dv/events", headers=auth_headers, params={"queryId": qid}
        ).json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_unknown_query_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(
            f"{BASE}/dv/events", headers=auth_headers, params={"queryId": "no-such-query"}
        )
        assert resp.status_code == 404

    def test_events_are_grounded_in_real_agents(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_ids = {a.id for a in agent_repo.list_all()}
        qid = _init_query(client, auth_headers)
        body = client.get(
            f"{BASE}/dv/events", headers=auth_headers, params={"queryId": qid}
        ).json()
        for event in body["data"]:
            assert event["agentId"] in agent_ids


class TestGetEventsByType:
    def test_returns_200_for_known_query(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        resp = client.get(f"{BASE}/dv/events/process", headers=auth_headers, params={"queryId": qid})
        assert resp.status_code == 200

    def test_returns_data_list(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        resp = client.get(f"{BASE}/dv/events/dns", headers=auth_headers, params={"queryId": qid})
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)

    def test_missing_id_returns_422(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/dv/events/process", headers=auth_headers)
        assert resp.status_code == 422

    def test_unknown_query_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(
            f"{BASE}/dv/events/process", headers=auth_headers, params={"queryId": "no-such-query"}
        )
        assert resp.status_code == 404


class TestCancelQuery:
    def test_cancel_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        resp = client.post(
            f"{BASE}/dv/cancel-query",
            headers=auth_headers,
            json={"queryId": qid},
        )
        assert resp.status_code == 200

    def test_cancel_via_data_key(self, client: TestClient, auth_headers: dict) -> None:
        qid = _init_query(client, auth_headers)
        resp = client.post(
            f"{BASE}/dv/cancel-query",
            headers=auth_headers,
            json={"data": {"queryId": qid}},
        )
        assert resp.status_code == 200

    def test_cancel_missing_query_id_returns_400(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.post(
            f"{BASE}/dv/cancel-query",
            headers=auth_headers,
            json={},
        )
        assert resp.status_code == 400
