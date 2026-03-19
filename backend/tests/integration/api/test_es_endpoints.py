"""Integration tests for Kibana Endpoint API.

Verifies endpoint metadata listing, single-endpoint retrieval, response
actions (isolate, unisolate), and action status tracking at
``/kibana/api/endpoint``.
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}

KBN_WRITE_HEADERS = {
    **ES_AUTH,
    "kbn-xsrf": "true",
}


def _get_first_endpoint_id(client: TestClient) -> str:
    """Return the agent_id of the first seeded endpoint."""
    body = client.get(
        "/kibana/api/endpoint/metadata",
        headers=ES_AUTH,
        params={"per_page": 1},
    ).json()
    return body["data"][0]["agent_id"]


class TestListEndpoints:
    """Tests for GET /kibana/api/endpoint/metadata."""

    def test_list_returns_200(self, client: TestClient) -> None:
        """Metadata listing should return 200 with valid auth."""
        resp = client.get("/kibana/api/endpoint/metadata", headers=ES_AUTH)
        assert resp.status_code == 200

    def test_list_has_kibana_pagination(self, client: TestClient) -> None:
        """Response must include page, per_page, total, and data."""
        body = client.get("/kibana/api/endpoint/metadata", headers=ES_AUTH).json()
        assert "page" in body
        assert "per_page" in body
        assert "total" in body
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_list_returns_seeded_endpoints(self, client: TestClient) -> None:
        """Total should match the number of seeded S1 agents (mapped to ES endpoints)."""
        body = client.get(
            "/kibana/api/endpoint/metadata",
            headers=ES_AUTH,
            params={"per_page": 200},
        ).json()
        # The seed maps all S1 agents to ES endpoints; there are 100 S1 agents
        assert body["total"] > 0

    def test_list_with_per_page(self, client: TestClient) -> None:
        """per_page should limit the number of results per page."""
        body = client.get(
            "/kibana/api/endpoint/metadata",
            headers=ES_AUTH,
            params={"per_page": 5},
        ).json()
        assert len(body["data"]) == 5

    def test_list_pagination_pages_are_disjoint(self, client: TestClient) -> None:
        """Page 1 and page 2 should return different endpoints."""
        p1 = client.get(
            "/kibana/api/endpoint/metadata",
            headers=ES_AUTH,
            params={"per_page": 5, "page": 1},
        ).json()["data"]
        p2 = client.get(
            "/kibana/api/endpoint/metadata",
            headers=ES_AUTH,
            params={"per_page": 5, "page": 2},
        ).json()["data"]
        ids1 = {ep["agent_id"] for ep in p1}
        ids2 = {ep["agent_id"] for ep in p2}
        assert ids1.isdisjoint(ids2)

    def test_endpoint_has_required_fields(self, client: TestClient) -> None:
        """Each endpoint must include key metadata fields."""
        body = client.get(
            "/kibana/api/endpoint/metadata",
            headers=ES_AUTH,
            params={"per_page": 1},
        ).json()
        ep = body["data"][0]
        required = [
            "agent_id", "hostname", "host_ip", "host_os_name",
            "agent_version", "agent_status", "policy_name",
            "isolation_status", "enrolled_at", "last_checkin",
        ]
        for field in required:
            assert field in ep, f"Missing endpoint field: {field}"


class TestGetEndpoint:
    """Tests for GET /kibana/api/endpoint/metadata/{agent_id}."""

    def test_get_endpoint_by_id(self, client: TestClient) -> None:
        """Getting an endpoint by its agent_id should return its metadata."""
        agent_id = _get_first_endpoint_id(client)
        resp = client.get(
            f"/kibana/api/endpoint/metadata/{agent_id}",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == agent_id

    def test_get_nonexistent_endpoint_returns_404(self, client: TestClient) -> None:
        """Non-existent agent_id should return 404."""
        resp = client.get(
            "/kibana/api/endpoint/metadata/does-not-exist",
            headers=ES_AUTH,
        )
        assert resp.status_code == 404


class TestIsolateEndpoint:
    """Tests for POST /kibana/api/endpoint/action/isolate."""

    def test_isolate_returns_action_response(self, client: TestClient) -> None:
        """Isolating an endpoint should return an action response dict."""
        agent_id = _get_first_endpoint_id(client)
        resp = client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id], "comment": "Isolate for investigation"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["agent_id"] == agent_id
        assert body["action"] == "isolate"
        assert body["status"] == "pending"

    def test_isolate_changes_isolation_status(self, client: TestClient) -> None:
        """After isolation, the endpoint isolation_status should be 'isolated'."""
        agent_id = _get_first_endpoint_id(client)
        client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id]},
        )
        ep = client.get(
            f"/kibana/api/endpoint/metadata/{agent_id}",
            headers=ES_AUTH,
        ).json()
        assert ep["isolation_status"] == "isolated"

    def test_isolate_nonexistent_returns_404(self, client: TestClient) -> None:
        """Isolating a non-existent endpoint should return 404."""
        resp = client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": ["does-not-exist"]},
        )
        assert resp.status_code == 404

    def test_isolate_missing_endpoint_ids_returns_400(self, client: TestClient) -> None:
        """Missing endpoint_ids should return 400."""
        resp = client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"comment": "no ids"},
        )
        assert resp.status_code == 400

    def test_isolate_without_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header should return 400."""
        agent_id = _get_first_endpoint_id(client)
        resp = client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=ES_AUTH,
            json={"endpoint_ids": [agent_id]},
        )
        assert resp.status_code == 400


class TestUnisolateEndpoint:
    """Tests for POST /kibana/api/endpoint/action/unisolate."""

    def test_unisolate_returns_action_response(self, client: TestClient) -> None:
        """Unisolating an endpoint should return an action response."""
        agent_id = _get_first_endpoint_id(client)
        # First isolate
        client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id]},
        )
        # Then unisolate
        resp = client.post(
            "/kibana/api/endpoint/action/unisolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id], "comment": "Release from isolation"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "unisolate"

    def test_unisolate_restores_normal_status(self, client: TestClient) -> None:
        """After unisolation, isolation_status should be 'normal'."""
        agent_id = _get_first_endpoint_id(client)
        client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id]},
        )
        client.post(
            "/kibana/api/endpoint/action/unisolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id]},
        )
        ep = client.get(
            f"/kibana/api/endpoint/metadata/{agent_id}",
            headers=ES_AUTH,
        ).json()
        assert ep["isolation_status"] == "normal"


class TestListActions:
    """Tests for GET /kibana/api/endpoint/action."""

    def test_list_actions_returns_200(self, client: TestClient) -> None:
        """Action listing should return 200."""
        resp = client.get("/kibana/api/endpoint/action", headers=ES_AUTH)
        assert resp.status_code == 200

    def test_list_actions_has_data_array(self, client: TestClient) -> None:
        """Response must include a 'data' list."""
        body = client.get("/kibana/api/endpoint/action", headers=ES_AUTH).json()
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_action_appears_after_isolate(self, client: TestClient) -> None:
        """After performing an isolate action, it should appear in the action list."""
        agent_id = _get_first_endpoint_id(client)
        client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id]},
        )
        body = client.get(
            "/kibana/api/endpoint/action",
            headers=ES_AUTH,
            params={"agent_id": agent_id},
        ).json()
        assert body["total"] >= 1
        actions = body["data"]
        action_types = [a["action"] for a in actions]
        assert "isolate" in action_types


class TestGetActionStatus:
    """Tests for GET /kibana/api/endpoint/action/{action_id}."""

    def test_get_action_by_id(self, client: TestClient) -> None:
        """Getting an action by its ID should return the action details."""
        agent_id = _get_first_endpoint_id(client)
        isolate_resp = client.post(
            "/kibana/api/endpoint/action/isolate",
            headers=KBN_WRITE_HEADERS,
            json={"endpoint_ids": [agent_id]},
        ).json()
        action_id = isolate_resp["id"]

        resp = client.get(
            f"/kibana/api/endpoint/action/{action_id}",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == action_id

    def test_get_nonexistent_action_returns_404(self, client: TestClient) -> None:
        """Non-existent action_id should return 404."""
        resp = client.get(
            "/kibana/api/endpoint/action/nonexistent-action-id",
            headers=ES_AUTH,
        )
        assert resp.status_code == 404
