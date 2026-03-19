"""Unit tests for the mockdr.testing public API.

These tests exercise :class:`mockdr.testing.MockdrClient` and
:func:`mockdr.testing._find_free_port` in isolation using
``httpx.MockTransport`` — no real server is started.

The :func:`mockdr.testing.mockdr_server` fixture is not covered here because
it requires a live uvicorn process; it is exercised implicitly by every
integration test that depends on it.
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from mockdr.testing import MockdrClient, _find_free_port

# ── Helpers ───────────────────────────────────────────────────────────────────


def _transport(responses: dict[tuple[str, str], httpx.Response]) -> httpx.MockTransport:
    """Build a ``httpx.MockTransport`` that dispatches by (method, path).

    Args:
        responses: Mapping of ``(HTTP_METHOD, /path)`` to the
            ``httpx.Response`` to return.

    Returns:
        A ``httpx.MockTransport`` instance.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        key = (request.method, request.url.path)
        if key in responses:
            return responses[key]
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


def _json_transport(
    responses: dict[tuple[str, str], dict[str, Any]],
    *,
    status: int = 200,
) -> httpx.MockTransport:
    """Convenience wrapper: build a transport from plain dicts.

    Args:
        responses: Mapping of ``(method, path)`` to a response body dict.
        status: HTTP status code to use for every response.

    Returns:
        A ``httpx.MockTransport`` instance.
    """
    return _transport(
        {k: httpx.Response(status, json=v) for k, v in responses.items()}
    )


def _make_client(
    responses: dict[tuple[str, str], dict[str, Any]],
    *,
    base_url: str = "http://test/web/api/v2.1",
    token: str = "admin-token-0000-0000-000000000001",
) -> MockdrClient:
    """Return a :class:`MockdrClient` wired to an in-process mock transport."""
    return MockdrClient(base_url, token=token, _transport=_json_transport(responses))


# ── _find_free_port ───────────────────────────────────────────────────────────


class TestFindFreePort:
    """Tests for the ``_find_free_port`` helper."""

    def test_returns_int(self) -> None:
        """Port must be an integer."""
        assert isinstance(_find_free_port(), int)

    def test_port_in_valid_range(self) -> None:
        """Port must be a valid non-privileged port number."""
        port = _find_free_port()
        assert 1024 <= port <= 65535

    def test_port_is_free(self) -> None:
        """Returned port must be bindable immediately after the call."""
        import socket

        port = _find_free_port()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", port))  # raises OSError if already in use

    def test_successive_calls_may_differ(self) -> None:
        """Two successive calls should not reliably return identical ports.

        This is probabilistic — the OS could reuse the same port, so we only
        assert that both calls succeed, not that they diverge.
        """
        port_a = _find_free_port()
        port_b = _find_free_port()
        assert isinstance(port_a, int)
        assert isinstance(port_b, int)


# ── MockdrClient construction ─────────────────────────────────────────────────


class TestMockdrClientConstruction:
    """Tests for :class:`MockdrClient` initialisation."""

    def test_stores_base_url(self) -> None:
        """``base_url`` attribute must match the constructor argument."""
        client = _make_client({})
        assert client.base_url == "http://test/web/api/v2.1"

    def test_stores_token(self) -> None:
        """``token`` attribute must match the constructor argument."""
        client = _make_client({}, token="my-token")
        assert client.token == "my-token"

    def test_default_token(self) -> None:
        """Default token is the well-known admin token."""
        client = MockdrClient(
            "http://test",
            _transport=_json_transport({}),
        )
        assert client.token == "admin-token-0000-0000-000000000001"


# ── MockdrClient.get ──────────────────────────────────────────────────────────


class TestMockdrClientGet:
    """Tests for :meth:`MockdrClient.get`."""

    def test_returns_json(self) -> None:
        """``get`` must return parsed JSON as a dict."""
        body = {"data": [{"id": "1"}], "pagination": {"totalItems": 1}}
        client = _make_client({("GET", "/web/api/v2.1/agents"): body})
        result = client.get("/agents")
        assert result == body

    def test_raises_on_4xx(self) -> None:
        """``get`` must raise ``httpx.HTTPStatusError`` on 4xx responses."""
        transport = _transport(
            {("GET", "/web/api/v2.1/agents"): httpx.Response(401, json={"error": "unauthorized"})}
        )
        client = MockdrClient("http://test/web/api/v2.1", _transport=transport)
        with pytest.raises(httpx.HTTPStatusError):
            client.get("/agents")

    def test_sends_auth_header(self) -> None:
        """``get`` must include the ``Authorization: ApiToken`` header."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            token="test-token",
            _transport=httpx.MockTransport(handler),
        )
        client.get("/agents")
        assert captured[0].headers["authorization"] == "ApiToken test-token"

    def test_forwards_query_params(self) -> None:
        """``get`` must forward ``params`` to the underlying request."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=httpx.MockTransport(handler),
        )
        client.get("/agents", params={"limit": "10"})
        assert "limit=10" in str(captured[0].url)


# ── MockdrClient.post ─────────────────────────────────────────────────────────


class TestMockdrClientPost:
    """Tests for :meth:`MockdrClient.post`."""

    def test_returns_json(self) -> None:
        """``post`` must return parsed JSON as a dict."""
        body = {"success": True}
        client = _make_client({("POST", "/web/api/v2.1/threats/mark-resolved"): body})
        result = client.post("/threats/mark-resolved", json={"filter": {}})
        assert result == body

    def test_raises_on_5xx(self) -> None:
        """``post`` must raise ``httpx.HTTPStatusError`` on 5xx responses."""
        transport = _transport(
            {("POST", "/web/api/v2.1/reset"): httpx.Response(500, json={})}
        )
        client = MockdrClient("http://test/web/api/v2.1", _transport=transport)
        with pytest.raises(httpx.HTTPStatusError):
            client.post("/reset")

    def test_sends_json_body(self) -> None:
        """``post`` must serialise the ``json=`` kwarg into the request body."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=httpx.MockTransport(handler),
        )
        payload = {"scenario": "mass_infection"}
        client.post("/_dev/scenario", json=payload)
        sent = json.loads(captured[0].content)
        assert sent == payload


# ── MockdrClient.put ──────────────────────────────────────────────────────────


class TestMockdrClientPut:
    """Tests for :meth:`MockdrClient.put`."""

    def test_returns_json(self) -> None:
        """``put`` must return parsed JSON as a dict."""
        body = {"updated": True}
        client = _make_client({("PUT", "/web/api/v2.1/agents/1/tag"): body})
        assert client.put("/agents/1/tag", json={}) == body

    def test_raises_on_4xx(self) -> None:
        """``put`` must propagate 4xx as ``httpx.HTTPStatusError``."""
        transport = _transport(
            {("PUT", "/web/api/v2.1/agents/1/tag"): httpx.Response(404, json={})}
        )
        client = MockdrClient("http://test/web/api/v2.1", _transport=transport)
        with pytest.raises(httpx.HTTPStatusError):
            client.put("/agents/1/tag", json={})


# ── MockdrClient.delete ───────────────────────────────────────────────────────


class TestMockdrClientDelete:
    """Tests for :meth:`MockdrClient.delete`."""

    def test_returns_json(self) -> None:
        """``delete`` must return parsed JSON as a dict."""
        body = {"deleted": 1}
        client = _make_client({("DELETE", "/web/api/v2.1/agents/1"): body})
        assert client.delete("/agents/1") == body

    def test_raises_on_4xx(self) -> None:
        """``delete`` must propagate 4xx as ``httpx.HTTPStatusError``."""
        transport = _transport(
            {("DELETE", "/web/api/v2.1/agents/1"): httpx.Response(403, json={})}
        )
        client = MockdrClient("http://test/web/api/v2.1", _transport=transport)
        with pytest.raises(httpx.HTTPStatusError):
            client.delete("/agents/1")


# ── MockdrClient convenience methods ─────────────────────────────────────────


class TestMockdrClientConvenienceMethods:
    """Tests for scenario, reset, export_state, import_state shortcuts."""

    def test_scenario_posts_to_dev_endpoint(self) -> None:
        """``scenario`` must POST ``{"scenario": name}`` to ``/_dev/scenario``."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={"triggered": True})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=httpx.MockTransport(handler),
        )
        result = client.scenario("mass_infection")
        assert result == {"triggered": True}
        assert captured[0].url.path == "/web/api/v2.1/_dev/scenario"
        assert json.loads(captured[0].content) == {"scenario": "mass_infection"}

    def test_reset_posts_to_dev_reset(self) -> None:
        """``reset`` must POST to ``/_dev/reset``."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={"reset": True})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=httpx.MockTransport(handler),
        )
        result = client.reset()
        assert result == {"reset": True}
        assert captured[0].url.path == "/web/api/v2.1/_dev/reset"

    def test_export_state_gets_dev_export(self) -> None:
        """``export_state`` must GET ``/_dev/export``."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={"agents": []})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=httpx.MockTransport(handler),
        )
        result = client.export_state()
        assert result == {"agents": []}
        assert captured[0].url.path == "/web/api/v2.1/_dev/export"
        assert captured[0].method == "GET"

    def test_import_state_posts_snapshot(self) -> None:
        """``import_state`` must POST the snapshot to ``/_dev/import``."""
        captured: list[httpx.Request] = []
        snapshot = {"agents": [{"id": "a1"}]}

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return httpx.Response(200, json={"imported": 1})

        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=httpx.MockTransport(handler),
        )
        result = client.import_state(snapshot)
        assert result == {"imported": 1}
        assert json.loads(captured[0].content) == snapshot


# ── MockdrClient.close ────────────────────────────────────────────────────────


class TestMockdrClientClose:
    """Tests for :meth:`MockdrClient.close`."""

    def test_close_is_idempotent(self) -> None:
        """Calling ``close`` twice must not raise."""
        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=_json_transport({}),
        )
        client.close()
        client.close()

    def test_close_prevents_further_requests(self) -> None:
        """Requests after ``close`` must raise ``RuntimeError``."""
        client = MockdrClient(
            "http://test/web/api/v2.1",
            _transport=_json_transport({("GET", "/web/api/v2.1/agents"): {}}),
        )
        client.close()
        with pytest.raises(RuntimeError):
            client.get("/agents")
