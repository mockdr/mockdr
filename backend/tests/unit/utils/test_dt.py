"""Unit tests for utils.dt — UTC timestamp helper."""
import re

from utils.dt import utc_now

_ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$")


class TestUtcNow:
    def test_returns_iso8601_string(self) -> None:
        ts = utc_now()
        assert isinstance(ts, str)
        assert _ISO_PATTERN.match(ts), f"Unexpected format: {ts}"

    def test_ends_with_000z(self) -> None:
        assert utc_now().endswith(".000Z")

    def test_two_calls_are_close(self) -> None:
        t1 = utc_now()
        t2 = utc_now()
        # Both should share the same date prefix at minimum
        assert t1[:10] == t2[:10]
