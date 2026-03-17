"""Unit tests for application.webhooks.commands — create, delete, fire_event."""
import hashlib
import hmac
import json
import threading
from unittest.mock import patch

import pytest

from application.webhooks.commands import create_webhook, delete_webhook, fire_event
from domain.webhook import ALL_EVENT_TYPES
from infrastructure.seed import generate_all
from repository.webhook_repo import webhook_repo


def _join_webhook_threads(timeout: float = 5.0) -> None:
    """Wait for all daemon webhook-delivery threads to finish."""
    for t in threading.enumerate():
        if t.daemon and t.is_alive() and t.name.startswith("Thread"):
            t.join(timeout=timeout)


@pytest.fixture(autouse=True)
def _seed() -> None:
    _join_webhook_threads()
    generate_all()


# ── create_webhook ───────────────────────────────────────────────────────────


class TestCreateWebhook:
    """Tests for the create_webhook command."""

    def test_returns_data_envelope(self) -> None:
        result = create_webhook({
            "url": "https://example.com/hook",
            "event_types": ["threat.created"],
        })
        assert "data" in result
        assert result["data"]["url"] == "https://example.com/hook"

    def test_assigns_id(self) -> None:
        result = create_webhook({"url": "https://example.com", "event_types": []})
        assert result["data"]["id"]

    def test_sets_timestamps(self) -> None:
        result = create_webhook({"url": "https://example.com", "event_types": []})
        assert result["data"]["createdAt"]
        assert result["data"]["updatedAt"]

    def test_default_active_true(self) -> None:
        result = create_webhook({"url": "https://example.com", "event_types": []})
        assert result["data"]["active"] is True

    def test_explicit_active_false(self) -> None:
        result = create_webhook({
            "url": "https://example.com", "event_types": [], "active": False,
        })
        assert result["data"]["active"] is False

    def test_stores_secret(self) -> None:
        result = create_webhook({
            "url": "https://example.com", "event_types": [], "secret": "s3cret",
        })
        # Response masks the secret for security
        assert result["data"]["secret"] == "****cret"
        # But the stored record retains the real secret
        sub = webhook_repo.get(result["data"]["id"])
        assert sub is not None
        assert sub.secret == "s3cret"

    def test_persists_to_repo(self) -> None:
        before = len(webhook_repo.list_all())
        create_webhook({"url": "https://example.com", "event_types": []})
        assert len(webhook_repo.list_all()) == before + 1

    def test_invalid_event_type_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid event types"):
            create_webhook({
                "url": "https://example.com",
                "event_types": ["not.valid"],
            })

    def test_all_valid_event_types_accepted(self) -> None:
        result = create_webhook({
            "url": "https://example.com",
            "event_types": list(ALL_EVENT_TYPES),
        })
        assert set(result["data"]["eventTypes"]) == ALL_EVENT_TYPES


# ── delete_webhook ───────────────────────────────────────────────────────────


class TestDeleteWebhook:
    """Tests for the delete_webhook command."""

    def test_deletes_existing(self) -> None:
        wh = create_webhook({"url": "https://example.com", "event_types": []})
        wh_id = wh["data"]["id"]
        result = delete_webhook(wh_id)
        assert result["data"]["affected"] == 1

    def test_delete_nonexistent_returns_zero(self) -> None:
        result = delete_webhook("does-not-exist")
        assert result["data"]["affected"] == 0

    def test_removes_from_repo(self) -> None:
        wh = create_webhook({"url": "https://example.com", "event_types": []})
        wh_id = wh["data"]["id"]
        delete_webhook(wh_id)
        assert webhook_repo.get(wh_id) is None


# ── fire_event ───────────────────────────────────────────────────────────────


class TestFireEvent:
    """Tests for the fire_event delivery logic."""

    def _create_sub(self, event_types: list[str], secret: str = "", active: bool = True) -> str:
        """Helper: create a subscription and return its ID."""
        result = create_webhook({
            "url": "https://example.com/hook",
            "event_types": event_types,
            "secret": secret,
            "active": active,
        })
        return result["data"]["id"]

    @patch("application.webhooks.commands.httpx.post")
    def test_delivers_to_matching_subscription(self, mock_post) -> None:
        self._create_sub(["threat.updated"])
        fire_event("threat.updated", {"id": "t1", "threatInfo": {}})
        _join_webhook_threads()
        mock_post.assert_called_once()

    @patch("application.webhooks.commands.httpx.post")
    def test_skips_non_matching_event_type(self, mock_post) -> None:
        self._create_sub(["threat.created"])  # not "threat.updated"
        fire_event("threat.updated", {"id": "t1"})
        mock_post.assert_not_called()

    @patch("application.webhooks.commands.httpx.post")
    def test_skips_inactive_subscription(self, mock_post) -> None:
        self._create_sub(["threat.updated"], active=False)
        fire_event("threat.updated", {"id": "t1"})
        mock_post.assert_not_called()

    @patch("application.webhooks.commands.httpx.post")
    def test_sends_bearer_auth_when_secret_set(self, mock_post) -> None:
        self._create_sub(["threat.updated"], secret="my-secret")
        fire_event("threat.updated", {"id": "t1"})
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers["Authorization"] == "Bearer my-secret"

    @patch("application.webhooks.commands.httpx.post")
    def test_sends_hmac_signature_when_secret_set(self, mock_post) -> None:
        self._create_sub(["threat.updated"], secret="my-secret")
        fire_event("threat.updated", {"id": "t1"})
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        body_json = call_kwargs.kwargs.get("content") or call_kwargs[1].get("content", "")
        expected_sig = hmac.new(
            b"my-secret", body_json.encode(), hashlib.sha256,
        ).hexdigest()
        assert headers["X-S1-Signature"] == f"sha256={expected_sig}"

    @patch("application.webhooks.commands.httpx.post")
    def test_no_auth_headers_when_no_secret(self, mock_post) -> None:
        self._create_sub(["threat.updated"], secret="")
        fire_event("threat.updated", {"id": "t1"})
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "Authorization" not in headers
        assert "X-S1-Signature" not in headers

    @patch("application.webhooks.commands.httpx.post")
    def test_event_type_header_set(self, mock_post) -> None:
        self._create_sub(["threat.updated"])
        fire_event("threat.updated", {"id": "t1"})
        call_kwargs = mock_post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers["X-S1-Webhook-Event"] == "threat.updated"

    @patch("application.webhooks.commands.httpx.post")
    def test_strips_threat_internal_fields(self, mock_post) -> None:
        """Threat payload must not include notes or timeline."""
        self._create_sub(["threat.updated"])
        fire_event("threat.updated", {"id": "t1", "notes": [{"text": "x"}], "timeline": []})
        call_kwargs = mock_post.call_args
        body_json = call_kwargs.kwargs.get("content") or call_kwargs[1].get("content", "")
        body = json.loads(body_json)
        assert "notes" not in body
        assert "timeline" not in body

    @patch("application.webhooks.commands.httpx.post")
    def test_strips_agent_internal_fields(self, mock_post) -> None:
        """Agent payload must not include passphrase or localIp."""
        self._create_sub(["agent.offline"])
        fire_event("agent.offline", {"id": "a1", "passphrase": "secret", "localIp": "10.0.0.1"})
        call_kwargs = mock_post.call_args
        body_json = call_kwargs.kwargs.get("content") or call_kwargs[1].get("content", "")
        body = json.loads(body_json)
        assert "passphrase" not in body
        assert "localIp" not in body

    @patch("application.webhooks.commands.httpx.post", side_effect=Exception("connection refused"))
    def test_delivery_failure_does_not_raise(self, mock_post) -> None:
        """Transport errors should be swallowed (best-effort delivery)."""
        self._create_sub(["threat.updated"])
        # Should not raise
        fire_event("threat.updated", {"id": "t1"})

    @patch("application.webhooks.commands.httpx.post")
    def test_no_subscriptions_is_noop(self, mock_post) -> None:
        """If no subscriptions exist, fire_event returns without calling httpx."""
        fire_event("threat.updated", {"id": "t1"})
        mock_post.assert_not_called()

    @patch("application.webhooks.commands.httpx.post")
    def test_multiple_subscriptions_all_called(self, mock_post) -> None:
        self._create_sub(["threat.updated"])
        self._create_sub(["threat.updated"])
        fire_event("threat.updated", {"id": "t1"})
        _join_webhook_threads()
        assert mock_post.call_count == 2
