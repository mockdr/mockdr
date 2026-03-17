"""Integration tests for the recording proxy management endpoints."""
from __future__ import annotations

import pytest

import application.proxy._state as _state
from application.proxy import commands as proxy_commands
from domain.proxy_recording import ProxyConfig, ProxyRecording


@pytest.fixture(autouse=True)
def reset_proxy(client: object) -> None:  # type: ignore[override]
    """Reset proxy state before each test."""
    _state._config = ProxyConfig(mode="off", base_url="", api_token="")
    _state._recordings.clear()


class TestProxyConfigEndpoints:
    def test_get_config_default(self, client, auth_headers) -> None:
        res = client.get("/web/api/v2.1/_dev/proxy/config", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["mode"] == "off"
        assert data["recording_count"] == 0

    def test_set_mode_record(self, client, auth_headers) -> None:
        res = client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={"mode": "record", "base_url": "https://example.sentinelone.net/web/api/v2.1"},
            headers=auth_headers,
        )
        assert res.status_code == 200
        assert res.json()["data"]["mode"] == "record"

    def test_set_mode_replay(self, client, auth_headers) -> None:
        res = client.post("/web/api/v2.1/_dev/proxy/config", json={"mode": "replay"}, headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["data"]["mode"] == "replay"

    def test_set_mode_off(self, client, auth_headers) -> None:
        res = client.post("/web/api/v2.1/_dev/proxy/config", json={"mode": "off"}, headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["data"]["mode"] == "off"

    def test_invalid_mode_returns_400(self, client, auth_headers) -> None:
        res = client.post("/web/api/v2.1/_dev/proxy/config", json={"mode": "hax"}, headers=auth_headers)
        assert res.status_code == 400

    def test_missing_mode_returns_400(self, client, auth_headers) -> None:
        res = client.post("/web/api/v2.1/_dev/proxy/config", json={}, headers=auth_headers)
        assert res.status_code == 400

    def test_token_masked_in_response(self, client, auth_headers) -> None:
        client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={"mode": "record", "api_token": "supersecrettoken"},
            headers=auth_headers,
        )
        res = client.get("/web/api/v2.1/_dev/proxy/config", headers=auth_headers)
        assert "supersecrettoken" not in res.json()["data"]["api_token"]


class TestProxyRecordingEndpoints:
    def _add_recording(self) -> None:
        proxy_commands.add_recording(ProxyRecording(
            id="r1", method="GET", path="/web/api/v2.1/threats",
            query_string="limit=25", request_body="",
            response_status=200, response_body='{"data":[]}',
            response_content_type="application/json",
            recorded_at="2026-01-01T00:00:00.000Z",
            base_url="https://example.sentinelone.net/web/api/v2.1",
        ))

    def test_list_empty(self, client, auth_headers) -> None:
        res = client.get("/web/api/v2.1/_dev/proxy/recordings", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["data"] == []

    def test_list_with_recording(self, client, auth_headers) -> None:
        self._add_recording()
        res = client.get("/web/api/v2.1/_dev/proxy/recordings", headers=auth_headers)
        assert res.status_code == 200
        assert len(res.json()["data"]) == 1
        assert res.json()["data"][0]["method"] == "GET"

    def test_clear_recordings(self, client, auth_headers) -> None:
        self._add_recording()
        res = client.delete("/web/api/v2.1/_dev/proxy/recordings", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["data"]["cleared"] == 1
        assert proxy_commands.clear_recordings() == 0

    def test_mode_off_does_not_intercept_mock(self, client, auth_headers) -> None:
        """With mode=off the mock still serves its own data."""
        res = client.get("/web/api/v2.1/threats", headers=auth_headers)
        assert res.status_code == 200
        assert "data" in res.json()

    def test_replay_serves_recording(self, client, auth_headers) -> None:
        """Replay mode returns the recorded response body."""
        proxy_commands.add_recording(ProxyRecording(
            id="r1", method="GET", path="/web/api/v2.1/threats",
            query_string="", request_body="",
            response_status=200,
            response_body='{"data": [{"id": "recorded-threat"}], "pagination": {"totalItems": 1}}',
            response_content_type="application/json",
            recorded_at="2026-01-01T00:00:00.000Z",
            base_url="https://example.sentinelone.net/web/api/v2.1",
        ))
        _state._config = ProxyConfig(mode="replay", base_url="", api_token="")
        res = client.get("/web/api/v2.1/threats", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["data"][0]["id"] == "recorded-threat"

    def test_replay_falls_through_to_mock_when_no_recording(self, client, auth_headers) -> None:
        """Replay mode falls back to mock when no recording matches."""
        _state._config = ProxyConfig(mode="replay", base_url="", api_token="")
        res = client.get("/web/api/v2.1/agents", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()["data"]
        assert isinstance(data, list)
        assert len(data) > 0  # mock data present

    def test_config_count_reflects_recordings(self, client, auth_headers) -> None:
        self._add_recording()
        self._add_recording()
        res = client.get("/web/api/v2.1/_dev/proxy/config", headers=auth_headers)
        assert res.json()["data"]["recording_count"] == 2
