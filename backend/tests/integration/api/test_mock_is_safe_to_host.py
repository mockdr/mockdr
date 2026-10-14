"""What a visitor to a shared or public mockdr can make the host do.

The admin token is a documented constant, so "admin only" keeps nobody out of
an instance others can reach. These tests hold the lines that matter anyway:
the mock never sends a request to a cloud metadata address, a public instance
(``MOCKDR_PUBLIC``) makes no outbound request and refuses the control routes
whose effect outlives one visitor, and nothing hands out the real-vendor
credentials the recording proxy holds.
"""
from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import application.proxy._state as proxy_state
import config
from application.webhooks import delivery_log
from application.webhooks.commands import fire_event, wait_for_deliveries
from domain.proxy_recording import ProxyConfig
from domain.webhook import WebhookSubscription
from repository.webhook_repo import webhook_repo

PROXY = "/web/api/v2.1/_dev/proxy/config"
ES_AUTH = ("elastic", "mock-elastic-password")


@pytest.fixture(autouse=True)
def proxy_off() -> Iterator[None]:
    """Every test starts and ends with the proxy off and no recordings."""
    proxy_state._config = ProxyConfig(mode="off")
    proxy_state._recordings.clear()
    yield
    proxy_state._config = ProxyConfig(mode="off")
    proxy_state._recordings.clear()


@pytest.fixture()
def public(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run as an instance started with MOCKDR_PUBLIC=true."""
    monkeypatch.setattr(config, "PUBLIC_MODE", True)


def _vendor(base_url: str, **auth: str) -> dict:
    return {"mode": "record", "vendors": [{
        "vendor": "s1", "base_url": base_url,
        "auth": auth or {"type": "api_token", "token": "real-tenant-token"},
        "enabled": True,
    }]}


# ── The recording proxy never targets a metadata service ────────────────────

@pytest.mark.parametrize("base_url", [
    "http://169.254.169.254",
    "http://[fe80::1]",
    "http://[fd00:ec2::254]",
    "http://[::ffff:169.254.169.254]",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379",
])
def test_proxy_refuses_a_metadata_or_non_http_upstream(
    client: TestClient, auth_headers: dict, base_url: str,
) -> None:
    resp = client.post(PROXY, headers=auth_headers, json=_vendor(base_url))
    assert resp.status_code == 400
    assert proxy_state._config.mode == "off"


def test_proxy_refuses_a_metadata_token_url(client: TestClient, auth_headers: dict) -> None:
    body = _vendor(
        "https://api.crowdstrike.example", type="oauth2", client_id="a",
        client_secret="b", token_url="http://169.254.169.254/latest/api/token",
    )
    assert client.post(PROXY, headers=auth_headers, json=body).status_code == 400


def test_proxy_refuses_the_legacy_flat_metadata_url(client: TestClient, auth_headers: dict) -> None:
    body = {"mode": "record", "base_url": "http://169.254.169.254", "api_token": "t"}
    assert client.post(PROXY, headers=auth_headers, json=body).status_code == 400


def test_a_name_resolving_to_metadata_is_refused_at_forward_time(
    client: TestClient, auth_headers: dict,
) -> None:
    """A host name is accepted at configuration, and resolved per request."""
    assert client.post(
        PROXY, headers=auth_headers, json=_vendor("http://rebind.example"),
    ).status_code == 200
    metadata = [(2, 1, 6, "", ("169.254.169.254", 80))]
    with patch("utils.egress.socket.getaddrinfo", return_value=metadata), \
            patch("httpx.AsyncClient.request") as upstream:
        resp = client.get("/web/api/v2.1/latest/meta-data/")
    assert resp.status_code == 502
    upstream.assert_not_called()


# ── Recordings are admin-only like the rest of /_dev ─────────────────────────

@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_a_viewer_cannot_read_or_wipe_recordings(
    client: TestClient, viewer_headers: dict, method: str,
) -> None:
    resp = client.request(method, "/web/api/v2.1/_dev/proxy/recordings", headers=viewer_headers)
    assert resp.status_code == 403


# ── Webhooks never target a metadata service ─────────────────────────────────

@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "file:///etc/passwd"])
def test_webhook_refuses_a_metadata_or_non_http_url(
    client: TestClient, auth_headers: dict, url: str,
) -> None:
    resp = client.post("/web/api/v2.1/_dev/webhooks", headers=auth_headers,
                       json={"url": url, "eventTypes": ["threat.created"]})
    assert resp.status_code == 400


def test_a_delivery_to_a_name_resolving_to_metadata_is_not_sent() -> None:
    webhook_repo.save(WebhookSubscription(
        id="rebind", url="http://rebind.example/hook", eventTypes=["threat.created"],
        secret="", active=True,
    ))
    delivery_log.clear()
    metadata = [(2, 1, 6, "", ("169.254.169.254", 80))]
    with patch("utils.egress.socket.getaddrinfo", return_value=metadata), \
            patch("application.webhooks.commands.httpx.post") as post:
        fire_event("threat.created", {"id": "t1"})
        wait_for_deliveries()
    post.assert_not_called()
    entries = delivery_log.list_entries()
    assert entries and "refused" in entries[0]["error"]


# ── A public instance ───────────────────────────────────────────────────────

@pytest.mark.usefixtures("public")
def test_public_instance_refuses_the_recording_proxy(
    client: TestClient, auth_headers: dict,
) -> None:
    resp = client.post(PROXY, headers=auth_headers, json=_vendor("https://tenant.example"))
    assert resp.status_code == 403
    assert client.post(PROXY, headers=auth_headers, json={"mode": "replay"}).status_code == 403
    assert proxy_state._config.mode == "off"


@pytest.mark.usefixtures("public")
def test_public_instance_refuses_webhook_subscriptions(
    client: TestClient, auth_headers: dict,
) -> None:
    resp = client.post("/web/api/v2.1/_dev/webhooks", headers=auth_headers,
                       json={"url": "https://receiver.example/hook", "eventTypes": ["threat.created"]})
    assert resp.status_code == 403
    assert webhook_repo.list_all() == []


@pytest.mark.usefixtures("public")
def test_public_instance_sends_no_webhook_that_already_exists() -> None:
    """A subscription from a snapshot or from before the switch still sends nothing."""
    webhook_repo.save(WebhookSubscription(
        id="old", url="https://receiver.example/hook", eventTypes=["threat.created"],
        secret="", active=True,
    ))
    with patch("application.webhooks.commands.httpx.post", return_value=MagicMock(status_code=200)) as post:
        fire_event("threat.created", {"id": "t1"})
        wait_for_deliveries()
    post.assert_not_called()


@pytest.mark.usefixtures("public")
@pytest.mark.parametrize(("path", "body"), [
    ("/web/api/v2.1/_dev/import", {}),
    ("/web/api/v2.1/_dev/rate-limit", {"enabled": True, "requestsPerMinute": 1}),
    ("/web/api/v2.1/_dev/fault-injection", {"errorRate": 1.0}),
])
def test_public_instance_refuses_routes_that_affect_every_visitor(
    client: TestClient, auth_headers: dict, path: str, body: dict,
) -> None:
    assert client.post(path, headers=auth_headers, json=body).status_code == 403


@pytest.mark.usefixtures("public")
def test_public_instance_still_resets_and_serves_the_mock(
    client: TestClient, auth_headers: dict,
) -> None:
    assert client.post("/web/api/v2.1/_dev/reset", headers=auth_headers).status_code == 200
    assert client.get("/web/api/v2.1/agents", headers=auth_headers).status_code == 200
