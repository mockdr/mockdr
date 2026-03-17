"""Integration tests for Splunk HEC endpoints."""
import json

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"
HEC_TOKEN = "11111111-1111-1111-1111-111111111111"


def _hec_auth(token: str = HEC_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Splunk {token}"}


class TestHecEvent:
    """Tests for POST /services/collector/event."""

    def test_submit_single_event(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({
                "event": {"message": "Test event", "severity": "info"},
                "sourcetype": "test:event",
                "index": "sentinelone",
            }),
            headers={**_hec_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0
        assert resp.json()["text"] == "Success"

    def test_submit_batched_events(self, client: TestClient) -> None:
        batch = "\n".join([
            json.dumps({"event": {"msg": "Event 1"}}),
            json.dumps({"event": {"msg": "Event 2"}}),
        ])
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=batch,
            headers={**_hec_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0

    def test_invalid_token_returns_403(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({"event": {"msg": "test"}}),
            headers={**_hec_auth("invalid-token"), "Content-Type": "application/json"},
        )
        assert resp.status_code == 403

    def test_missing_auth_returns_401(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({"event": {"msg": "test"}}),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 401

    def test_invalid_json_returns_400(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content="not json",
            headers={**_hec_auth(), "Content-Type": "application/json"},
        )
        assert resp.status_code == 400


class TestHecRaw:
    """Tests for POST /services/collector/raw."""

    def test_submit_raw_event(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/raw",
            content="Raw log line from test",
            headers={**_hec_auth(), "Content-Type": "text/plain"},
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0


class TestHecHealth:
    """Tests for GET /services/collector/health."""

    def test_health_check(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/collector/health")
        assert resp.status_code == 200
        assert resp.json()["code"] == 17


class TestHecAck:
    """Tests for POST /services/collector/ack."""

    def test_ack_check(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/ack",
            json={"acks": [0, 1, 2]},
            headers=_hec_auth(),
        )
        assert resp.status_code == 200
        acks = resp.json()["acks"]
        assert acks["0"] is True
        assert acks["1"] is True
