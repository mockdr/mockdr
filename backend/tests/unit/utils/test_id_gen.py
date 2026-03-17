"""Unit tests for utils.id_gen — SentinelOne-style ID generation."""
from utils.id_gen import new_id


class TestNewId:
    """Tests for the new_id function."""

    def test_returns_string(self) -> None:
        assert isinstance(new_id(), str)

    def test_is_numeric(self) -> None:
        """Generated IDs must be composed entirely of digits."""
        result = new_id()
        assert result.isdigit(), f"Expected all digits, got: {result}"

    def test_is_18_digits(self) -> None:
        """SentinelOne IDs are 18-digit numbers (range 10^17 to 10^18-1)."""
        result = new_id()
        assert len(result) == 18, f"Expected 18 digits, got {len(result)}: {result}"

    def test_two_calls_produce_different_ids(self) -> None:
        """IDs should be unique (probabilistically — collision on 10^17 range is negligible)."""
        ids = {new_id() for _ in range(100)}
        assert len(ids) == 100, "Expected 100 unique IDs"

    def test_no_leading_zero(self) -> None:
        """The range 10^17..10^18-1 guarantees no leading zero."""
        for _ in range(50):
            assert not new_id().startswith("0")
