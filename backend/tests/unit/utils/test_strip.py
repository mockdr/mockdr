"""Unit tests for utils.strip — strip_fields utility."""
from utils.strip import strip_fields


class TestStripFields:
    """Tests for the strip_fields function."""

    def test_removes_listed_fields(self) -> None:
        record = {"id": "1", "name": "Alice", "passphrase": "secret", "localIp": "10.0.0.1"}
        internal = frozenset({"passphrase", "localIp"})
        result = strip_fields(record, internal)
        assert "passphrase" not in result
        assert "localIp" not in result

    def test_preserves_public_fields(self) -> None:
        record = {"id": "1", "name": "Alice", "passphrase": "secret"}
        internal = frozenset({"passphrase"})
        result = strip_fields(record, internal)
        assert result == {"id": "1", "name": "Alice"}

    def test_empty_internal_set_returns_full_record(self) -> None:
        record = {"id": "1", "name": "Alice"}
        result = strip_fields(record, frozenset())
        assert result == record

    def test_returns_new_dict(self) -> None:
        """strip_fields must return a new dict, not mutate the original."""
        record = {"id": "1", "secret": "x"}
        result = strip_fields(record, frozenset({"secret"}))
        assert "secret" in record  # original unchanged
        assert "secret" not in result

    def test_field_not_present_is_harmless(self) -> None:
        """Stripping a field that doesn't exist in the record is a no-op."""
        record = {"id": "1", "name": "Alice"}
        result = strip_fields(record, frozenset({"nonexistent", "also_missing"}))
        assert result == {"id": "1", "name": "Alice"}

    def test_all_fields_stripped_returns_empty_dict(self) -> None:
        record = {"a": 1, "b": 2}
        result = strip_fields(record, frozenset({"a", "b"}))
        assert result == {}

    def test_empty_record_returns_empty(self) -> None:
        result = strip_fields({}, frozenset({"anything"}))
        assert result == {}
