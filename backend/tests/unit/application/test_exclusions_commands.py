"""Unit tests for application.exclusions.commands — exclusion CRUD."""
import pytest

from application.exclusions.commands import create_exclusion, delete_exclusion
from infrastructure.seed import generate_all
from repository.activity_repo import activity_repo
from repository.exclusion_repo import exclusion_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_exclusion_id() -> str:
    return exclusion_repo.list_all()[0].id


# ── create_exclusion ────────────────────────────────────────────────────────


class TestCreateExclusion:
    """Tests for the create_exclusion command."""

    def test_returns_data_as_list(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp/test", "type": "path"}}, "user-1")
        assert "data" in result
        assert isinstance(result["data"], list)
        assert len(result["data"]) == 1

    def test_assigns_id(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp/test"}}, "user-1")
        assert result["data"][0]["id"]

    def test_sets_value_and_type(self) -> None:
        result = create_exclusion(
            {"data": {"value": "C:\\Windows\\Temp", "type": "path"}}, "user-1",
        )
        assert result["data"][0]["value"] == "C:\\Windows\\Temp"
        assert result["data"][0]["type"] == "path"

    def test_default_type_is_path(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, "user-1")
        assert result["data"][0]["type"] == "path"

    def test_default_os_type(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, "user-1")
        assert result["data"][0]["osType"] == "any"

    def test_explicit_os_type(self) -> None:
        result = create_exclusion(
            {"data": {"value": "/tmp", "osType": "windows"}}, "user-1",
        )
        assert result["data"][0]["osType"] == "windows"

    def test_default_mode_is_suppress(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, "user-1")
        assert result["data"][0]["mode"] == "suppress"

    def test_sets_user_id(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, "user-42")
        assert result["data"][0]["userId"] == "user-42"

    def test_none_user_id_becomes_empty_string(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, None)
        assert result["data"][0]["userId"] == ""

    def test_sets_timestamps(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, "u1")
        assert result["data"][0]["createdAt"]
        assert result["data"][0]["updatedAt"]

    def test_persisted_to_repo(self) -> None:
        before = len(exclusion_repo.list_all())
        create_exclusion({"data": {"value": "/new/path"}}, "u1")
        assert len(exclusion_repo.list_all()) == before + 1

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        create_exclusion({"data": {"value": "/tmp"}}, "u1")
        assert len(activity_repo.list_all()) > before

    def test_unwraps_data_key(self) -> None:
        """Body with nested data key is unwrapped correctly."""
        result = create_exclusion(
            {"data": {"value": "/nested", "type": "file_type"}}, "u1",
        )
        assert result["data"][0]["value"] == "/nested"
        assert result["data"][0]["type"] == "file_type"

    def test_flat_body_accepted(self) -> None:
        """Body without data wrapper is accepted as-is."""
        result = create_exclusion({"value": "/flat", "type": "path"}, "u1")
        assert result["data"][0]["value"] == "/flat"

    def test_description_set(self) -> None:
        result = create_exclusion(
            {"data": {"value": "/tmp", "description": "Test exclusion"}}, "u1",
        )
        assert result["data"][0]["description"] == "Test exclusion"

    def test_scope_defaults(self) -> None:
        result = create_exclusion({"data": {"value": "/tmp"}}, "u1")
        assert result["data"][0]["scopeName"] == "Global"
        assert result["data"][0]["scopePath"] == "Global"

    def test_site_id_set(self) -> None:
        result = create_exclusion(
            {"data": {"value": "/tmp", "siteId": "site-123"}}, "u1",
        )
        assert result["data"][0]["siteId"] == "site-123"


# ── delete_exclusion ────────────────────────────────────────────────────────


class TestDeleteExclusion:
    """Tests for the delete_exclusion command."""

    def test_deletes_existing(self) -> None:
        eid = _first_exclusion_id()
        result = delete_exclusion(eid)
        assert result["data"]["affected"] == 1

    def test_exclusion_removed_from_repo(self) -> None:
        eid = _first_exclusion_id()
        delete_exclusion(eid)
        assert exclusion_repo.get(eid) is None

    def test_nonexistent_returns_zero(self) -> None:
        result = delete_exclusion("does-not-exist")
        assert result["data"]["affected"] == 0

    def test_double_delete_returns_zero(self) -> None:
        eid = _first_exclusion_id()
        delete_exclusion(eid)
        result = delete_exclusion(eid)
        assert result["data"]["affected"] == 0
