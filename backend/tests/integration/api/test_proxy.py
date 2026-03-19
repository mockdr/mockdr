"""Integration tests for the recording proxy management endpoints."""
from __future__ import annotations

import pytest

import application.proxy._state as _state
from application.proxy import commands as proxy_commands
from domain.proxy_recording import (
    AuthApiToken,
    AuthOAuth2,
    ProxyConfig,
    ProxyRecording,
    VendorProxyConfig,
)


@pytest.fixture(autouse=True)
def reset_proxy(client: object) -> None:  # type: ignore[override]
    """Reset proxy state before each test."""
    _state._config = ProxyConfig(mode="off")
    _state._recordings.clear()


class TestProxyConfigEndpoints:
    def test_get_config_default(self, client, auth_headers) -> None:
        res = client.get("/web/api/v2.1/_dev/proxy/config", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["mode"] == "off"
        assert data["recording_count"] == 0
        assert "vendors" in data

    def test_set_mode_record(self, client, auth_headers) -> None:
        res = client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={"mode": "record"},
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

    def test_set_per_vendor_config(self, client, auth_headers) -> None:
        res = client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={
                "mode": "record",
                "vendors": [
                    {
                        "vendor": "crowdstrike",
                        "base_url": "https://api.crowdstrike.com",
                        "auth": {
                            "type": "oauth2",
                            "client_id": "test-id",
                            "client_secret": "test-secret",
                            "token_url": "https://api.crowdstrike.com/oauth2/token",
                        },
                    },
                ],
            },
            headers=auth_headers,
        )
        assert res.status_code == 200
        vendors = res.json()["data"]["vendors"]
        assert "crowdstrike" in vendors
        assert vendors["crowdstrike"]["base_url"] == "https://api.crowdstrike.com"
        # Secret should be masked.
        assert "test-secret" not in vendors["crowdstrike"]["auth"]["client_secret"]

    def test_multiple_vendors(self, client, auth_headers) -> None:
        res = client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={
                "mode": "record",
                "vendors": [
                    {
                        "vendor": "s1",
                        "base_url": "https://tenant.sentinelone.net",
                        "auth": {"type": "api_token", "token": "real-s1-token"},
                    },
                    {
                        "vendor": "mde",
                        "base_url": "https://api.securitycenter.microsoft.com",
                        "auth": {
                            "type": "oauth2",
                            "client_id": "mde-id",
                            "client_secret": "mde-secret",
                            "token_url": "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
                        },
                    },
                ],
            },
            headers=auth_headers,
        )
        assert res.status_code == 200
        vendors = res.json()["data"]["vendors"]
        assert "s1" in vendors
        assert "mde" in vendors

    def test_invalid_vendor_returns_400(self, client, auth_headers) -> None:
        res = client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={
                "mode": "record",
                "vendors": [{"vendor": "nonexistent", "base_url": "https://example.com"}],
            },
            headers=auth_headers,
        )
        assert res.status_code == 400

    def test_legacy_flat_config_migrates_to_s1(self, client, auth_headers) -> None:
        """Legacy base_url/api_token params should be stored under the s1 vendor."""
        res = client.post(
            "/web/api/v2.1/_dev/proxy/config",
            json={
                "mode": "record",
                "base_url": "https://tenant.sentinelone.net/web/api/v2.1",
                "api_token": "legacy-token",
            },
            headers=auth_headers,
        )
        assert res.status_code == 200
        vendors = res.json()["data"]["vendors"]
        assert "s1" in vendors
        assert vendors["s1"]["base_url"] == "https://tenant.sentinelone.net/web/api/v2.1"


class TestProxyRecordingEndpoints:
    def _add_recording(self, vendor: str = "s1") -> None:
        proxy_commands.add_recording(ProxyRecording(
            id="r1", method="GET", path="/web/api/v2.1/threats",
            query_string="limit=25", request_body="",
            response_status=200, response_body='{"data":[]}',
            response_content_type="application/json",
            recorded_at="2026-01-01T00:00:00.000Z",
            base_url="https://example.sentinelone.net/web/api/v2.1",
            vendor=vendor,
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
        assert res.json()["data"][0]["vendor"] == "s1"

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
            vendor="s1",
        ))
        _state._config = ProxyConfig(
            mode="replay",
            vendors={"s1": VendorProxyConfig(vendor="s1", base_url="https://example.sentinelone.net", auth=AuthApiToken(token="t"), enabled=True)},
        )
        res = client.get("/web/api/v2.1/threats", headers=auth_headers)
        assert res.status_code == 200
        assert res.json()["data"][0]["id"] == "recorded-threat"

    def test_replay_falls_through_to_mock_when_no_recording(self, client, auth_headers) -> None:
        """Replay mode falls back to mock when no recording matches."""
        _state._config = ProxyConfig(
            mode="replay",
            vendors={"s1": VendorProxyConfig(vendor="s1", base_url="https://example.sentinelone.net", auth=AuthApiToken(token="t"), enabled=True)},
        )
        res = client.get("/web/api/v2.1/agents", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()["data"]
        assert isinstance(data, list)
        assert len(data) > 0  # mock data present

    def test_replay_vendor_isolation(self, client, auth_headers) -> None:
        """A recording for one vendor does not replay for another vendor's path."""
        proxy_commands.add_recording(ProxyRecording(
            id="r-cs", method="GET", path="/cs/devices/queries/devices/v1",
            query_string="", request_body="",
            response_status=200, response_body='{"resources": ["cs-recorded"]}',
            response_content_type="application/json",
            recorded_at="2026-01-01T00:00:00.000Z",
            base_url="https://api.crowdstrike.com",
            vendor="crowdstrike",
        ))
        _state._config = ProxyConfig(
            mode="replay",
            vendors={
                "crowdstrike": VendorProxyConfig(
                    vendor="crowdstrike",
                    base_url="https://api.crowdstrike.com",
                    auth=AuthOAuth2(client_id="id", client_secret="secret", token_url="https://api.crowdstrike.com/oauth2/token"),
                    enabled=True,
                ),
            },
        )
        # The CS recording exists, so this should replay.
        res = client.get("/cs/devices/queries/devices/v1", headers=auth_headers)
        assert res.status_code == 200

    def test_config_count_reflects_recordings(self, client, auth_headers) -> None:
        self._add_recording()
        self._add_recording()
        res = client.get("/web/api/v2.1/_dev/proxy/config", headers=auth_headers)
        assert res.json()["data"]["recording_count"] == 2


class TestProxyVendorListEndpoint:
    def test_list_vendors(self, client, auth_headers) -> None:
        res = client.get("/web/api/v2.1/_dev/proxy/vendors", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()["data"]
        vendors = {v["vendor"] for v in data}
        assert "s1" in vendors
        assert "crowdstrike" in vendors
        assert "mde" in vendors
        assert "elastic" in vendors
        assert "cortex_xdr" in vendors
        assert "splunk" in vendors
        assert "sentinel" in vendors
        assert "graph" in vendors
        # Each entry should have a label and default auth type.
        for v in data:
            assert "label" in v
            assert "default_auth_type" in v
