"""Unit tests for RecordingProxyMiddleware.

These tests mock httpx so no live endpoint is required.

Covered paths:
- Non-HTTP scope passthrough (WebSocket / lifespan)
- mode=off passthrough
- mode=record: success -> recording stored, response forwarded
- mode=record: upstream failure -> 502 returned
- mode=record: query string appended to URL
- mode=replay: recording found -> served
- mode=replay: no recording -> falls through to app
- _read_body: single chunk, multi-chunk
- _record_and_forward: response content-type forwarded
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import application.proxy._state as _state
from api.middleware.proxy import (
    RecordingProxyMiddleware,
    _read_body,
    _record_and_forward,
)
from application.proxy import commands as proxy_commands
from application.proxy.token_cache import OAuth2TokenCache
from domain.proxy_recording import (
    AuthApiToken,
    ProxyConfig,
    ProxyRecording,
    VendorProxyConfig,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_S1_VENDOR_CFG = VendorProxyConfig(
    vendor="s1",
    base_url="https://example.test",
    auth=AuthApiToken(token="fake-token"),
    enabled=True,
)


@pytest.fixture(autouse=True)
def reset_proxy_state() -> None:
    """Isolate proxy state between tests."""
    _state._config = ProxyConfig(mode="off")
    _state._recordings.clear()


def _make_scope(
    path: str = "/web/api/v2.1/threats",
    method: str = "GET",
    query: bytes = b"",
    scope_type: str = "http",
) -> dict:
    return {
        "type": scope_type,
        "method": method,
        "path": path,
        "query_string": query,
    }


def _make_receive(body: bytes = b"") -> AsyncMock:
    """Single-chunk receive callable."""
    msg = {"body": body, "more_body": False}
    return AsyncMock(return_value=msg)


def _make_multi_receive(chunks: list[bytes]) -> AsyncMock:
    """Multi-chunk receive callable."""
    messages = [{"body": c, "more_body": True} for c in chunks[:-1]]
    messages.append({"body": chunks[-1], "more_body": False})
    return AsyncMock(side_effect=messages)


def _make_send() -> tuple[AsyncMock, list[dict]]:
    collected: list[dict] = []

    async def send(msg: dict) -> None:
        collected.append(msg)

    return send, collected  # type: ignore[return-value]


def _fake_response(
    status: int = 200,
    body: str = '{"data":[]}',
    content_type: str = "application/json",
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    resp.content = body.encode()
    resp.headers = {"content-type": content_type}
    return resp


def _set_record_mode() -> None:
    """Set proxy to record mode with S1 vendor configured."""
    _state._config = ProxyConfig(
        mode="record",
        vendors={"s1": _S1_VENDOR_CFG},
    )


def _set_replay_mode() -> None:
    """Set proxy to replay mode with S1 vendor configured."""
    _state._config = ProxyConfig(
        mode="replay",
        vendors={"s1": _S1_VENDOR_CFG},
    )


# ── Non-HTTP scope ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_non_http_scope_passes_through() -> None:
    """WebSocket / lifespan scopes bypass the middleware entirely."""
    inner_called = []

    async def inner_app(scope, receive, send):  # type: ignore[no-untyped-def]
        inner_called.append(scope["type"])

    mw = RecordingProxyMiddleware(inner_app)
    scope = _make_scope(scope_type="websocket")
    await mw(scope, AsyncMock(), AsyncMock())
    assert inner_called == ["websocket"]


# ── mode=off ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_mode_off_passes_to_inner_app() -> None:
    inner_called = []

    async def inner_app(scope, receive, send):  # type: ignore[no-untyped-def]
        inner_called.append(True)

    _state._config = ProxyConfig(mode="off")
    mw = RecordingProxyMiddleware(inner_app)
    await mw(_make_scope(), _make_receive(), AsyncMock())
    assert inner_called


@pytest.mark.asyncio
async def test_dev_path_always_passes_through_in_record_mode() -> None:
    """/_dev/ paths skip recording even in record mode."""
    inner_called = []

    async def inner_app(scope, receive, send):  # type: ignore[no-untyped-def]
        inner_called.append(True)

    _set_record_mode()
    mw = RecordingProxyMiddleware(inner_app)
    scope = _make_scope(path="/web/api/v2.1/_dev/reset")
    await mw(scope, _make_receive(), AsyncMock())
    assert inner_called


# ── mode=record: success ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_record_mode_stores_recording() -> None:
    """Successful upstream call stores one recording."""
    _set_record_mode()

    fake_resp = _fake_response(200, '{"data":[]}')
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=fake_resp)

    send, collected = _make_send()

    with patch("httpx.AsyncClient", return_value=mock_client):
        mw = RecordingProxyMiddleware(AsyncMock())
        await mw(_make_scope(), _make_receive(b""), send)

    assert len(_state._recordings) == 1
    rec = _state._recordings[0]
    assert rec.method == "GET"
    assert rec.path == "/web/api/v2.1/threats"
    assert rec.response_status == 200
    assert rec.vendor == "s1"


@pytest.mark.asyncio
async def test_record_mode_forwards_response_to_client() -> None:
    """The proxied response body is sent back to the caller."""
    _set_record_mode()

    payload = '{"data": [{"id": "t1"}], "pagination": {"totalItems": 1}}'
    fake_resp = _fake_response(200, payload)
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=fake_resp)

    send, collected = _make_send()

    with patch("httpx.AsyncClient", return_value=mock_client):
        mw = RecordingProxyMiddleware(AsyncMock())
        await mw(_make_scope(), _make_receive(b""), send)

    assert collected[0]["status"] == 200
    body_msg = collected[1]["body"]
    assert b"t1" in body_msg


@pytest.mark.asyncio
async def test_record_mode_appends_query_string_to_url() -> None:
    """Query string is forwarded to upstream."""
    _set_record_mode()

    fake_resp = _fake_response()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=fake_resp)

    send, _ = _make_send()
    scope = _make_scope(query=b"limit=10&siteIds=abc")

    with patch("httpx.AsyncClient", return_value=mock_client):
        mw = RecordingProxyMiddleware(AsyncMock())
        await mw(scope, _make_receive(), send)

    call_kwargs = mock_client.request.call_args
    url_used = call_kwargs.kwargs.get("url") or call_kwargs.args[1]
    assert "limit=10" in url_used


@pytest.mark.asyncio
async def test_record_mode_upstream_failure_returns_502() -> None:
    """If httpx raises, the middleware returns 502 Bad Gateway."""
    _set_record_mode()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(side_effect=ConnectionError("refused"))

    send, collected = _make_send()

    with patch("httpx.AsyncClient", return_value=mock_client):
        mw = RecordingProxyMiddleware(AsyncMock())
        await mw(_make_scope(), _make_receive(), send)

    assert collected[0]["status"] == 502
    body = json.loads(collected[1]["body"])
    assert body["errors"][0]["code"] == 5020001


@pytest.mark.asyncio
async def test_record_mode_preserves_content_type() -> None:
    """Non-JSON content-type from upstream is stored in the recording."""
    _set_record_mode()

    fake_resp = _fake_response(200, "ok", "text/plain; charset=utf-8")
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=fake_resp)

    send, _ = _make_send()

    with patch("httpx.AsyncClient", return_value=mock_client):
        mw = RecordingProxyMiddleware(AsyncMock())
        await mw(_make_scope(), _make_receive(), send)

    rec = _state._recordings[0]
    assert rec.response_content_type == "text/plain; charset=utf-8"


# ── mode=replay ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_replay_mode_serves_stored_recording() -> None:
    """Replay mode returns the stored response body."""
    _set_replay_mode()
    proxy_commands.add_recording(ProxyRecording(
        id="r1", method="GET", path="/web/api/v2.1/threats",
        query_string="", request_body="",
        response_status=200,
        response_body='{"data": [{"id": "replay-threat"}]}',
        response_content_type="application/json",
        recorded_at="2026-01-01T00:00:00.000Z",
        base_url="https://example.test",
        vendor="s1",
    ))

    send, collected = _make_send()
    mw = RecordingProxyMiddleware(AsyncMock())
    await mw(_make_scope(), _make_receive(), send)

    assert collected[0]["status"] == 200
    assert b"replay-threat" in collected[1]["body"]


@pytest.mark.asyncio
async def test_replay_mode_falls_through_when_no_match() -> None:
    """Replay with no matching recording delegates to the inner app."""
    _set_replay_mode()
    inner_called = []

    async def inner_app(scope, receive, send):  # type: ignore[no-untyped-def]
        inner_called.append(True)

    mw = RecordingProxyMiddleware(inner_app)
    await mw(
        _make_scope(path="/web/api/v2.1/agents"),
        _make_receive(),
        AsyncMock(),
    )
    assert inner_called


# ── _read_body ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_read_body_single_chunk() -> None:
    receive = _make_receive(b'{"key":"value"}')
    result = await _read_body(receive)
    assert result == b'{"key":"value"}'


@pytest.mark.asyncio
async def test_read_body_multiple_chunks() -> None:
    receive = _make_multi_receive([b"chunk1", b"chunk2", b"chunk3"])
    result = await _read_body(receive)
    assert result == b"chunk1chunk2chunk3"


@pytest.mark.asyncio
async def test_read_body_empty() -> None:
    receive = _make_receive(b"")
    result = await _read_body(receive)
    assert result == b""


# ── _record_and_forward standalone ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_record_and_forward_returns_true_on_success() -> None:
    fake_resp = _fake_response(201, '{"data": "created"}')
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=fake_resp)

    send, _ = _make_send()

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await _record_and_forward(
            method="POST",
            path="/web/api/v2.1/threats/mitigate/quarantine",
            query_str="",
            body=b'{"filter":{"ids":["t1"]},"data":{}}',
            vendor="s1",
            vendor_cfg=_S1_VENDOR_CFG,
            token_cache=OAuth2TokenCache(),
            send=send,
        )

    assert result is True


@pytest.mark.asyncio
async def test_record_and_forward_returns_false_on_exception() -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(side_effect=TimeoutError("timed out"))

    send, _ = _make_send()

    with patch("httpx.AsyncClient", return_value=mock_client):
        result = await _record_and_forward(
            method="GET",
            path="/web/api/v2.1/agents",
            query_str="",
            body=b"",
            vendor="s1",
            vendor_cfg=_S1_VENDOR_CFG,
            token_cache=OAuth2TokenCache(),
            send=send,
        )

    assert result is False


@pytest.mark.asyncio
async def test_record_and_forward_stores_request_body_in_recording() -> None:
    fake_resp = _fake_response()
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=fake_resp)

    send, _ = _make_send()
    request_body = b'{"filter":{"ids":["abc"]}}'

    with patch("httpx.AsyncClient", return_value=mock_client):
        await _record_and_forward(
            method="POST",
            path="/web/api/v2.1/threats/analyst-verdict",
            query_str="",
            body=request_body,
            vendor="s1",
            vendor_cfg=_S1_VENDOR_CFG,
            token_cache=OAuth2TokenCache(),
            send=send,
        )

    rec = _state._recordings[0]
    assert '{"filter":{"ids":["abc"]}}' in rec.request_body
