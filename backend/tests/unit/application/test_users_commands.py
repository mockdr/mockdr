"""Unit tests for application.users.commands — user CRUD and token management."""
import pytest

from application.users.commands import (
    bulk_delete_users,
    create_user,
    delete_user,
    generate_api_token,
    get_api_token_details,
    update_user,
)
from infrastructure.seed import generate_all
from repository.store import store
from repository.user_repo import user_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_user_id() -> str:
    return user_repo.list_all()[0].id


# ── create_user ─────────────────────────────────────────────────────────────


class TestCreateUser:
    """Tests for the create_user command."""

    def test_returns_data_envelope(self) -> None:
        result = create_user({"email": "new@acme.com", "fullName": "New User"})
        assert "data" in result

    def test_assigns_id(self) -> None:
        result = create_user({"email": "new@acme.com", "fullName": "New User"})
        assert result["data"]["id"]

    def test_sets_email_and_name(self) -> None:
        result = create_user({"email": "test@acme.com", "fullName": "Test User"})
        assert result["data"]["email"] == "test@acme.com"
        assert result["data"]["fullName"] == "Test User"

    def test_default_role_is_viewer(self) -> None:
        """Role is internal-stripped from response; verify via repo."""
        result = create_user({"email": "v@acme.com"})
        uid = result["data"]["id"]
        assert user_repo.get(uid).role == "Viewer"

    def test_explicit_role(self) -> None:
        """Role is internal-stripped from response; verify via repo."""
        result = create_user({"email": "a@acme.com", "role": "Admin"})
        uid = result["data"]["id"]
        assert user_repo.get(uid).role == "Admin"

    def test_exposes_api_token_at_creation(self) -> None:
        result = create_user({"email": "new@acme.com"})
        assert result["data"]["apiToken"]
        assert len(result["data"]["apiToken"]) > 0

    def test_token_stored_in_api_tokens(self) -> None:
        result = create_user({"email": "new@acme.com"})
        token = result["data"]["apiToken"]
        record = store.get("api_tokens", token)
        assert record is not None
        assert record["token"] == token

    def test_user_persisted_in_repo(self) -> None:
        before = len(user_repo.list_all())
        create_user({"email": "new@acme.com"})
        assert len(user_repo.list_all()) == before + 1

    def test_internal_fields_stripped(self) -> None:
        result = create_user({"email": "new@acme.com"})
        # _apiToken is internal and should not leak (apiToken is the creation-time exposure)
        assert "_apiToken" not in result["data"]

    def test_sets_date_joined(self) -> None:
        result = create_user({"email": "new@acme.com"})
        assert result["data"]["dateJoined"]

    def test_sets_account_from_store(self) -> None:
        """accountId/accountName are internal-stripped; verify via repo."""
        result = create_user({"email": "new@acme.com"})
        uid = result["data"]["id"]
        user = user_repo.get(uid)
        assert user.accountId
        assert user.accountName

    def test_scope_roles_default(self) -> None:
        result = create_user({"email": "new@acme.com"})
        assert isinstance(result["data"]["scopeRoles"], list)
        assert len(result["data"]["scopeRoles"]) > 0

    def test_custom_scope(self) -> None:
        result = create_user({"email": "new@acme.com", "scope": "site"})
        assert result["data"]["scope"] == "site"


# ── update_user ─────────────────────────────────────────────────────────────


class TestUpdateUser:
    """Tests for the update_user command."""

    def test_updates_full_name(self) -> None:
        uid = _first_user_id()
        result = update_user(uid, {"fullName": "Updated Name"})
        assert result is not None
        assert result["data"]["fullName"] == "Updated Name"

    def test_updates_email(self) -> None:
        uid = _first_user_id()
        result = update_user(uid, {"email": "updated@acme.com"})
        assert result["data"]["email"] == "updated@acme.com"

    def test_updates_role_and_lowest_role(self) -> None:
        uid = _first_user_id()
        update_user(uid, {"role": "IR Team"})
        user = user_repo.get(uid)
        assert user.role == "IR Team"
        assert user.lowestRole == "IR Team"

    def test_updates_two_fa_enabled(self) -> None:
        uid = _first_user_id()
        update_user(uid, {"twoFaEnabled": True})
        assert user_repo.get(uid).twoFaEnabled is True

    def test_partial_update_preserves_other_fields(self) -> None:
        uid = _first_user_id()
        old_email = user_repo.get(uid).email
        update_user(uid, {"fullName": "Only Name Changed"})
        assert user_repo.get(uid).email == old_email

    def test_nonexistent_user_returns_none(self) -> None:
        result = update_user("does-not-exist", {"fullName": "X"})
        assert result is None

    def test_internal_fields_stripped_from_response(self) -> None:
        uid = _first_user_id()
        result = update_user(uid, {"fullName": "X"})
        assert "_apiToken" not in result["data"]


# ── delete_user ─────────────────────────────────────────────────────────────


class TestDeleteUser:
    """Tests for the delete_user command."""

    def test_deletes_existing_user(self) -> None:
        uid = _first_user_id()
        result = delete_user(uid)
        assert result["data"]["affected"] == 1

    def test_user_removed_from_repo(self) -> None:
        uid = _first_user_id()
        delete_user(uid)
        assert user_repo.get(uid) is None

    def test_token_removed_from_store(self) -> None:
        uid = _first_user_id()
        user = user_repo.get(uid)
        token = user._apiToken
        delete_user(uid)
        assert store.get("api_tokens", token) is None

    def test_nonexistent_user_returns_zero(self) -> None:
        result = delete_user("does-not-exist")
        assert result["data"]["affected"] == 0


# ── bulk_delete_users ───────────────────────────────────────────────────────


class TestBulkDeleteUsers:
    """Tests for the bulk_delete_users command."""

    def test_deletes_multiple(self) -> None:
        ids = [u.id for u in user_repo.list_all()[:2]]
        result = bulk_delete_users(ids)
        assert result["data"]["affected"] == 2

    def test_mixed_valid_invalid(self) -> None:
        valid_id = _first_user_id()
        result = bulk_delete_users([valid_id, "fake-id"])
        assert result["data"]["affected"] == 1

    def test_empty_list(self) -> None:
        result = bulk_delete_users([])
        assert result["data"]["affected"] == 0


# ── generate_api_token ──────────────────────────────────────────────────────


class TestGenerateApiToken:
    """Tests for the generate_api_token command."""

    def test_returns_new_token(self) -> None:
        uid = _first_user_id()
        result = generate_api_token(uid)
        assert result is not None
        assert "data" in result
        assert result["data"]["token"]
        assert result["data"]["expiresAt"]

    def test_new_token_differs_from_old(self) -> None:
        uid = _first_user_id()
        old_token = user_repo.get(uid)._apiToken
        result = generate_api_token(uid)
        assert result["data"]["token"] != old_token

    def test_old_token_revoked(self) -> None:
        uid = _first_user_id()
        old_token = user_repo.get(uid)._apiToken
        generate_api_token(uid)
        assert store.get("api_tokens", old_token) is None

    def test_new_token_stored(self) -> None:
        uid = _first_user_id()
        result = generate_api_token(uid)
        new_token = result["data"]["token"]
        record = store.get("api_tokens", new_token)
        assert record is not None
        assert record["userId"] == uid

    def test_nonexistent_user_returns_none(self) -> None:
        result = generate_api_token("does-not-exist")
        assert result is None


# ── get_api_token_details ───────────────────────────────────────────────────


class TestGetApiTokenDetails:
    """Tests for the get_api_token_details command."""

    def test_returns_token_details(self) -> None:
        uid = _first_user_id()
        result = get_api_token_details(uid)
        assert result is not None
        assert result["data"]["userId"] == uid
        assert result["data"]["token"]

    def test_nonexistent_user_returns_none(self) -> None:
        result = get_api_token_details("does-not-exist")
        assert result is None
