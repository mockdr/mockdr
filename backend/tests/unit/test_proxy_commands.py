"""Unit tests for recording proxy application commands and queries."""
from __future__ import annotations

import pytest

import application.proxy._state as _state
from application.proxy import commands as proxy_commands
from application.proxy import queries as proxy_queries
from domain.proxy_recording import ProxyConfig, ProxyRecording


@pytest.fixture(autouse=True)
def reset_proxy_state() -> None:
    """Reset proxy state before each test."""
    _state._config = ProxyConfig(mode="off", base_url="", api_token="")  # type: ignore[attr-defined]
    _state._recordings.clear()


class TestProxyConfig:
    def test_default_mode_is_off(self) -> None:
        cfg = proxy_queries.get_config()
        assert cfg.mode == "off"

    def test_set_record_mode(self) -> None:
        proxy_commands.set_config("record", "https://tenant.sentinelone.net/web/api/v2.1", "real-token")
        cfg = proxy_queries.get_config_raw()
        assert cfg.mode == "record"
        assert cfg.base_url == "https://tenant.sentinelone.net/web/api/v2.1"
        assert cfg.api_token == "real-token"

    def test_set_replay_mode(self) -> None:
        proxy_commands.set_config("replay")
        assert proxy_queries.get_config_raw().mode == "replay"

    def test_invalid_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid mode"):
            proxy_commands.set_config("invalid")

    def test_token_is_masked_in_get_config(self) -> None:
        proxy_commands.set_config("record", api_token="supersecrettoken")
        cfg = proxy_queries.get_config()
        assert "supersecrettoken" not in cfg.api_token
        assert cfg.api_token.startswith("...")

    def test_short_token_is_fully_masked(self) -> None:
        proxy_commands.set_config("record", api_token="abc")
        assert proxy_queries.get_config().api_token == "***"

    def test_empty_base_url_keeps_existing(self) -> None:
        proxy_commands.set_config("record", base_url="https://original.example.com/web/api/v2.1")
        proxy_commands.set_config("replay", base_url="")
        assert proxy_queries.get_config_raw().base_url == "https://original.example.com/web/api/v2.1"

    def test_base_url_trailing_slash_stripped(self) -> None:
        proxy_commands.set_config("record", base_url="https://example.com/web/api/v2.1/")
        assert proxy_queries.get_config_raw().base_url == "https://example.com/web/api/v2.1"


class TestRecordings:
    def _make_recording(self, method: str = "GET", path: str = "/web/api/v2.1/threats") -> ProxyRecording:
        return ProxyRecording(
            id="rec-1",
            method=method,
            path=path,
            query_string="limit=25",
            request_body="",
            response_status=200,
            response_body='{"data": []}',
            response_content_type="application/json",
            recorded_at="2026-01-01T00:00:00.000Z",
            base_url="https://example.sentinelone.net/web/api/v2.1",
        )

    def test_add_and_list(self) -> None:
        proxy_commands.add_recording(self._make_recording())
        assert proxy_queries.recording_count() == 1

    def test_list_newest_first(self) -> None:
        r1 = self._make_recording()
        r2 = ProxyRecording(**{**r1.__dict__, "id": "rec-2", "path": "/web/api/v2.1/agents"})
        proxy_commands.add_recording(r1)
        proxy_commands.add_recording(r2)
        listed = proxy_queries.list_recordings()
        assert listed[0].id == "rec-2"
        assert listed[1].id == "rec-1"

    def test_find_recording_match(self) -> None:
        proxy_commands.add_recording(self._make_recording("GET", "/web/api/v2.1/threats"))
        found = proxy_queries.find_recording("GET", "/web/api/v2.1/threats")
        assert found is not None
        assert found.method == "GET"

    def test_find_recording_no_match(self) -> None:
        proxy_commands.add_recording(self._make_recording("GET", "/web/api/v2.1/threats"))
        assert proxy_queries.find_recording("POST", "/web/api/v2.1/threats") is None

    def test_find_recording_returns_most_recent(self) -> None:
        r1 = self._make_recording()
        r2 = ProxyRecording(**{**r1.__dict__, "id": "rec-2", "response_status": 201})
        proxy_commands.add_recording(r1)
        proxy_commands.add_recording(r2)
        found = proxy_queries.find_recording("GET", "/web/api/v2.1/threats")
        assert found is not None
        assert found.id == "rec-2"

    def test_clear_recordings(self) -> None:
        proxy_commands.add_recording(self._make_recording())
        proxy_commands.add_recording(self._make_recording())
        cleared = proxy_commands.clear_recordings()
        assert cleared == 2
        assert proxy_queries.recording_count() == 0
