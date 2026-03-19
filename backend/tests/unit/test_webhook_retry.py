"""Unit tests for webhook retry logic and delivery log."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from application.webhooks.commands import (
    MAX_RETRIES,
    _deliver_with_retries,
    create_webhook,
    fire_event,
)
from application.webhooks.delivery_log import DeliveryEntry, clear, list_entries, record
from infrastructure.seed import generate_all
from repository.webhook_repo import webhook_repo


@pytest.fixture(autouse=True)
def _seed_and_clear_log() -> None:
    generate_all()
    clear()


def _make_sub(event_types: list[str], secret: str = "") -> str:
    """Create a subscription and return its ID."""
    result = create_webhook({
        "url": "https://example.com/hook",
        "event_types": event_types,
        "secret": secret,
    })
    return result["data"]["id"]


# ── DeliveryLog ring buffer ──────────────────────────────────────────────────


class TestDeliveryLog:
    """Tests for the in-memory delivery log ring buffer."""

    def test_record_and_list(self) -> None:
        entry = DeliveryEntry(
            subscription_id="s1",
            event_type="threat.created",
            status="success",
            attempt=1,
            timestamp="2025-01-01T00:00:00Z",
        )
        record(entry)
        entries = list_entries()
        assert len(entries) == 1
        assert entries[0]["subscription_id"] == "s1"

    def test_newest_first(self) -> None:
        for i in range(3):
            record(DeliveryEntry(
                subscription_id=f"s{i}",
                event_type="threat.created",
                status="success",
                attempt=1,
                timestamp=f"2025-01-0{i + 1}T00:00:00Z",
            ))
        entries = list_entries()
        assert entries[0]["subscription_id"] == "s2"
        assert entries[2]["subscription_id"] == "s0"

    def test_cap_at_100(self) -> None:
        for i in range(120):
            record(DeliveryEntry(
                subscription_id=f"s{i}",
                event_type="threat.created",
                status="success",
                attempt=1,
                timestamp="2025-01-01T00:00:00Z",
            ))
        assert len(list_entries()) == 100

    def test_clear(self) -> None:
        record(DeliveryEntry(
            subscription_id="s1",
            event_type="threat.created",
            status="success",
            attempt=1,
            timestamp="2025-01-01T00:00:00Z",
        ))
        count = clear()
        assert count == 1
        assert len(list_entries()) == 0


# ── Retry logic (_deliver_with_retries) ──────────────────────────────────────


class TestDeliverWithRetries:
    """Tests for the synchronous _deliver_with_retries helper."""

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post")
    def test_success_on_first_attempt(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        sub_id = _make_sub(["threat.updated"])
        sub = webhook_repo.get(sub_id)
        _deliver_with_retries("threat.updated", sub, '{"id":"t1"}', {})
        mock_post.assert_called_once()
        mock_sleep.assert_not_called()
        entries = list_entries()
        assert len(entries) == 1
        assert entries[0]["status"] == "success"
        assert entries[0]["attempt"] == 1

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post")
    def test_success_on_second_attempt(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        mock_post.side_effect = [Exception("fail"), MagicMock()]
        sub_id = _make_sub(["threat.updated"])
        sub = webhook_repo.get(sub_id)
        _deliver_with_retries("threat.updated", sub, '{"id":"t1"}', {})
        assert mock_post.call_count == 2
        mock_sleep.assert_called_once_with(1)  # backoff: 1s
        entries = list_entries()
        assert len(entries) == 2
        assert entries[0]["status"] == "success"  # newest first
        assert entries[0]["attempt"] == 2
        assert entries[1]["status"] == "failure"
        assert entries[1]["attempt"] == 1

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post")
    def test_success_on_third_attempt(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        mock_post.side_effect = [Exception("fail1"), Exception("fail2"), MagicMock()]
        sub_id = _make_sub(["threat.updated"])
        sub = webhook_repo.get(sub_id)
        _deliver_with_retries("threat.updated", sub, '{"id":"t1"}', {})
        assert mock_post.call_count == 3
        assert mock_sleep.call_count == 2
        mock_sleep.assert_any_call(1)  # first backoff
        mock_sleep.assert_any_call(2)  # second backoff

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post", side_effect=Exception("always fail"))
    def test_all_retries_exhausted(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        sub_id = _make_sub(["threat.updated"])
        sub = webhook_repo.get(sub_id)
        _deliver_with_retries("threat.updated", sub, '{"id":"t1"}', {})
        assert mock_post.call_count == MAX_RETRIES
        entries = list_entries()
        assert len(entries) == MAX_RETRIES
        assert all(e["status"] == "failure" for e in entries)
        # Check error messages are recorded
        assert all(e["error"] == "always fail" for e in entries)

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post", side_effect=Exception("fail"))
    def test_exponential_backoff_delays(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        sub_id = _make_sub(["threat.updated"])
        sub = webhook_repo.get(sub_id)
        _deliver_with_retries("threat.updated", sub, '{"id":"t1"}', {})
        # Should sleep between attempts 1->2 and 2->3 but NOT after final failure
        delays = [call.args[0] for call in mock_sleep.call_args_list]
        assert delays == [1, 2]  # 1s, 2s (4s would be after 3rd if there was a 4th)


# ── fire_event with threads ──────────────────────────────────────────────────


class TestFireEventRetry:
    """Tests for fire_event dispatching to background threads."""

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_records_delivery(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        """fire_event should record delivery entries via background thread."""
        _make_sub(["threat.updated"])
        # Patch threading.Thread to run target synchronously for test determinism
        with patch("application.webhooks.commands.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            # Capture the target function and call it inline
            def run_inline(**kwargs: object) -> MagicMock:
                m = MagicMock()
                m.start = lambda: kwargs["target"](*kwargs["args"])
                return m
            mock_thread.side_effect = run_inline

            fire_event("threat.updated", {"id": "t1"})
        entries = list_entries()
        assert len(entries) == 1
        assert entries[0]["status"] == "success"

    @patch("application.webhooks.commands.time.sleep")
    @patch("application.webhooks.commands.httpx.post", side_effect=Exception("fail"))
    def test_fire_event_retries_on_failure(self, mock_post: MagicMock, mock_sleep: MagicMock) -> None:
        _make_sub(["threat.updated"])
        with patch("application.webhooks.commands.threading.Thread") as mock_thread:
            def run_inline(**kwargs: object) -> MagicMock:
                m = MagicMock()
                m.start = lambda: kwargs["target"](*kwargs["args"])
                return m
            mock_thread.side_effect = run_inline

            fire_event("threat.updated", {"id": "t1"})
        assert mock_post.call_count == MAX_RETRIES
        entries = list_entries()
        assert len(entries) == MAX_RETRIES
        assert all(e["status"] == "failure" for e in entries)

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_spawns_daemon_thread(self, mock_post: MagicMock) -> None:
        _make_sub(["threat.updated"])
        with patch("application.webhooks.commands.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            fire_event("threat.updated", {"id": "t1"})
            mock_thread.assert_called_once()
            call_kwargs = mock_thread.call_args.kwargs
            assert call_kwargs["daemon"] is True

    @patch("application.webhooks.commands.httpx.post")
    def test_fire_event_no_subs_no_thread(self, mock_post: MagicMock) -> None:
        with patch("application.webhooks.commands.threading.Thread") as mock_thread:
            fire_event("threat.updated", {"id": "t1"})
            mock_thread.assert_not_called()
