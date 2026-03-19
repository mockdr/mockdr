"""Integration tests for webhook subscription endpoints.

GET    /web/api/v2.1/webhooks          — list subscriptions
POST   /web/api/v2.1/webhooks          — create subscription
GET    /web/api/v2.1/webhooks/{id}     — get single subscription
DELETE /web/api/v2.1/webhooks/{id}     — delete subscription
"""
from fastapi.testclient import TestClient

_VALID_PAYLOAD = {
    "url": "https://example.com/webhook",
    "event_types": ["threat.created"],
    "secret": "mysecret",
    "description": "Test subscription",
}


class TestListWebhooks:
    """Tests for GET /web/api/v2.1/webhooks."""

    def test_requires_auth(self, client: TestClient) -> None:
        resp = client.get("/web/api/v2.1/webhooks")
        assert resp.status_code == 401

    def test_returns_empty_list_initially(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get("/web/api/v2.1/webhooks", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"] == []


class TestCreateWebhook:
    """Tests for POST /web/api/v2.1/webhooks."""

    def test_creates_subscription(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            "/web/api/v2.1/webhooks", headers=auth_headers, json=_VALID_PAYLOAD
        )
        assert resp.status_code == 200
        body = resp.json()["data"]
        assert body["url"] == _VALID_PAYLOAD["url"]
        assert body["eventTypes"] == _VALID_PAYLOAD["event_types"]
        assert "id" in body

    def test_created_subscription_appears_in_list(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        client.post("/web/api/v2.1/webhooks", headers=auth_headers, json=_VALID_PAYLOAD)
        resp = client.get("/web/api/v2.1/webhooks", headers=auth_headers)
        assert len(resp.json()["data"]) == 1

    def test_invalid_event_type_returns_400(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        payload = dict(_VALID_PAYLOAD, event_types=["not.a.valid.event"])
        resp = client.post("/web/api/v2.1/webhooks", headers=auth_headers, json=payload)
        assert resp.status_code == 400

    def test_all_valid_event_types_accepted(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        payload = dict(_VALID_PAYLOAD, event_types=[
            "threat.created", "threat.updated", "alert.created",
            "agent.offline", "agent.infected",
        ])
        resp = client.post("/web/api/v2.1/webhooks", headers=auth_headers, json=payload)
        assert resp.status_code == 200


class TestGetWebhook:
    """Tests for GET /web/api/v2.1/webhooks/{id}."""

    def test_returns_subscription(self, client: TestClient, auth_headers: dict) -> None:
        created = client.post(
            "/web/api/v2.1/webhooks", headers=auth_headers, json=_VALID_PAYLOAD
        ).json()["data"]
        webhook_id = created["id"]

        resp = client.get(f"/web/api/v2.1/webhooks/{webhook_id}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == webhook_id

    def test_unknown_id_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/webhooks/does-not-exist", headers=auth_headers)
        assert resp.status_code == 404


class TestDeleteWebhook:
    """Tests for DELETE /web/api/v2.1/webhooks/{id}."""

    def test_deletes_subscription(self, client: TestClient, auth_headers: dict) -> None:
        created = client.post(
            "/web/api/v2.1/webhooks", headers=auth_headers, json=_VALID_PAYLOAD
        ).json()["data"]
        webhook_id = created["id"]

        del_resp = client.delete(
            f"/web/api/v2.1/webhooks/{webhook_id}", headers=auth_headers
        )
        assert del_resp.status_code == 200
        assert del_resp.json()["data"]["affected"] == 1

        # Verify it's gone
        get_resp = client.get(
            f"/web/api/v2.1/webhooks/{webhook_id}", headers=auth_headers
        )
        assert get_resp.status_code == 404

    def test_delete_non_existent_returns_zero_affected(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.delete("/web/api/v2.1/webhooks/does-not-exist", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 0
