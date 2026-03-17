"""Tests for webhook delivery including HMAC-SHA256 signing."""
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

from application.webhooks.commands import fire_event
from domain.webhook import WebhookSubscription
from repository.webhook_repo import webhook_repo


class TestWebhookDelivery:
    """Test that fire_event delivers payloads with correct headers and HMAC."""

    def _create_subscription(
        self, url: str = "http://test-receiver.local/hook",
        secret: str = "my-secret-key",
        event_types: list | None = None,
    ) -> WebhookSubscription:
        sub = WebhookSubscription(
            id="test-sub-1",
            url=url,
            eventTypes=event_types or ["threat.created"],
            secret=secret,
            active=True,
        )
        webhook_repo.save(sub)
        return sub

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_sends_post_to_subscriber(self, mock_post: MagicMock) -> None:
        """fire_event should POST to the subscriber URL."""
        self._create_subscription()
        fire_event("threat.created", {"id": "t1", "threatInfo": {"threatName": "test"}})

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs.get("timeout") == 5.0
        # URL should be the subscriber URL
        assert call_kwargs.args[0] == "http://test-receiver.local/hook"

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_includes_event_type_header(self, mock_post: MagicMock) -> None:
        """The X-S1-Webhook-Event header should contain the event type."""
        self._create_subscription()
        fire_event("threat.created", {"id": "t1"})

        headers = mock_post.call_args.kwargs.get("headers", {})
        assert headers["X-S1-Webhook-Event"] == "threat.created"

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_includes_bearer_auth(self, mock_post: MagicMock) -> None:
        """Secret should be sent as Bearer token in Authorization header."""
        self._create_subscription(secret="webhook-secret-123")
        fire_event("threat.created", {"id": "t1"})

        headers = mock_post.call_args.kwargs.get("headers", {})
        assert headers["Authorization"] == "Bearer webhook-secret-123"

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_includes_hmac_signature(self, mock_post: MagicMock) -> None:
        """X-S1-Signature should contain a valid HMAC-SHA256 of the body."""
        secret = "hmac-test-secret"
        self._create_subscription(secret=secret)
        payload = {"id": "t1", "threatInfo": {"threatName": "Trojan.GenericKD"}}
        fire_event("threat.created", payload)

        call_kwargs = mock_post.call_args
        body_json = call_kwargs.kwargs.get("content", "")
        headers = call_kwargs.kwargs.get("headers", {})

        # Verify the signature matches
        expected_sig = hmac.new(
            secret.encode(), body_json.encode(), hashlib.sha256
        ).hexdigest()
        assert headers["X-S1-Signature"] == f"sha256={expected_sig}"

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_without_secret_has_no_auth_headers(self, mock_post: MagicMock) -> None:
        """Subscriptions without a secret should not have auth headers."""
        self._create_subscription(secret="")
        fire_event("threat.created", {"id": "t1"})

        headers = mock_post.call_args.kwargs.get("headers", {})
        assert "Authorization" not in headers
        assert "X-S1-Signature" not in headers

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_only_targets_matching_subscribers(self, mock_post: MagicMock) -> None:
        """Only subscriptions matching the event type should receive the event."""
        self._create_subscription(event_types=["alert.created"])
        fire_event("threat.created", {"id": "t1"})
        mock_post.assert_not_called()

    @patch("application.webhooks.commands.httpx.post", side_effect=ConnectionError("refused"))
    def test_fire_event_logs_delivery_failure(self, mock_post: MagicMock) -> None:
        """Delivery failures should be logged, not raised."""
        self._create_subscription()
        # Should not raise
        fire_event("threat.created", {"id": "t1"})

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_strips_internal_threat_fields(self, mock_post: MagicMock) -> None:
        """Internal fields (notes, timeline) should be stripped from threat payloads."""
        self._create_subscription()
        payload = {"id": "t1", "threatInfo": {}, "notes": ["secret"], "timeline": []}
        fire_event("threat.created", payload)

        body_json = mock_post.call_args.kwargs.get("content", "")
        body = json.loads(body_json)
        assert "notes" not in body
        assert "timeline" not in body
        assert "id" in body
