"""Unit tests for application.sites.commands — site CRUD and lifecycle."""
import pytest

from application.sites.commands import (
    create_site,
    delete_site,
    expire_site,
    reactivate_site,
    update_site,
)
from infrastructure.seed import generate_all
from repository.account_repo import account_repo
from repository.site_repo import site_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_site_id() -> str:
    return site_repo.list_all()[0].id


def _non_default_site_id() -> str:
    """Return the ID of a non-default site, or skip if none exists."""
    for s in site_repo.list_all():
        if not s.isDefault:
            return s.id
    pytest.skip("No non-default site in seed data")


def _default_site_id() -> str:
    """Return the ID of the default site."""
    for s in site_repo.list_all():
        if s.isDefault:
            return s.id
    pytest.skip("No default site in seed data")


def _account_id() -> str:
    accounts = account_repo.list_all()
    return accounts[0].id if accounts else ""


# ── create_site ─────────────────────────────────────────────────────────────


class TestCreateSite:
    """Tests for the create_site command."""

    def test_returns_data_envelope(self) -> None:
        result = create_site({
            "name": "Test Site",
            "accountId": _account_id(),
            "totalLicenses": 100,
        })
        assert "data" in result

    def test_assigns_id(self) -> None:
        result = create_site({"name": "New Site", "accountId": _account_id()})
        assert result["data"]["id"]

    def test_sets_name(self) -> None:
        result = create_site({"name": "My Site", "accountId": _account_id()})
        assert result["data"]["name"] == "My Site"

    def test_default_state_is_active(self) -> None:
        result = create_site({"name": "Active Site", "accountId": _account_id()})
        assert result["data"]["state"] == "active"

    def test_sets_total_licenses(self) -> None:
        result = create_site({
            "name": "Licensed Site",
            "accountId": _account_id(),
            "totalLicenses": 250,
        })
        assert result["data"]["totalLicenses"] == 250

    def test_active_licenses_starts_at_zero(self) -> None:
        result = create_site({"name": "New", "accountId": _account_id()})
        assert result["data"]["activeLicenses"] == 0

    def test_default_sku_and_suite(self) -> None:
        result = create_site({"name": "Defaults", "accountId": _account_id()})
        assert result["data"]["sku"] == "Complete"
        assert result["data"]["suite"] == "Complete"

    def test_explicit_sku_and_suite(self) -> None:
        result = create_site({
            "name": "Custom",
            "accountId": _account_id(),
            "sku": "Control",
            "suite": "Control",
        })
        assert result["data"]["sku"] == "Control"
        assert result["data"]["suite"] == "Control"

    def test_is_not_default(self) -> None:
        result = create_site({"name": "Non-default", "accountId": _account_id()})
        assert result["data"]["isDefault"] is False

    def test_persisted_to_repo(self) -> None:
        before = len(site_repo.list_all())
        create_site({"name": "Persisted", "accountId": _account_id()})
        assert len(site_repo.list_all()) == before + 1

    def test_sets_timestamps(self) -> None:
        result = create_site({"name": "Timestamped", "accountId": _account_id()})
        assert result["data"]["createdAt"]
        assert result["data"]["updatedAt"]

    def test_sets_registration_token(self) -> None:
        result = create_site({"name": "Reg", "accountId": _account_id()})
        assert result["data"]["registrationToken"]

    def test_resolves_account_name(self) -> None:
        acct_id = _account_id()
        result = create_site({"name": "Acct", "accountId": acct_id})
        assert result["data"]["accountName"]

    def test_internal_fields_stripped(self) -> None:
        result = create_site({"name": "Stripped", "accountId": _account_id()})
        # Site internal fields should not appear
        assert "siteId" not in result["data"]  # siteId is internal on sites


# ── update_site ─────────────────────────────────────────────────────────────


class TestUpdateSite:
    """Tests for the update_site command."""

    def test_updates_name(self) -> None:
        sid = _first_site_id()
        result = update_site(sid, {"name": "Renamed Site"})
        assert result is not None
        assert result["data"]["name"] == "Renamed Site"

    def test_updates_description(self) -> None:
        sid = _first_site_id()
        result = update_site(sid, {"description": "New desc"})
        assert result["data"]["description"] == "New desc"

    def test_updates_state(self) -> None:
        sid = _first_site_id()
        update_site(sid, {"state": "expired"})
        assert site_repo.get(sid).state == "expired"

    def test_updates_total_licenses(self) -> None:
        sid = _first_site_id()
        update_site(sid, {"totalLicenses": 999})
        assert site_repo.get(sid).totalLicenses == 999

    def test_partial_update_preserves_other_fields(self) -> None:
        sid = _first_site_id()
        old_name = site_repo.get(sid).name
        update_site(sid, {"description": "Only desc changed"})
        assert site_repo.get(sid).name == old_name

    def test_updates_timestamp(self) -> None:
        sid = _first_site_id()
        old_updated = site_repo.get(sid).updatedAt
        update_site(sid, {"name": "Timestamp Test"})
        assert site_repo.get(sid).updatedAt >= old_updated

    def test_nonexistent_site_returns_none(self) -> None:
        result = update_site("does-not-exist", {"name": "X"})
        assert result is None

    def test_updatable_fields(self) -> None:
        """Verify all updatable fields can be set."""
        sid = _first_site_id()
        update_site(sid, {
            "name": "All fields",
            "description": "desc",
            "siteType": "Trial",
            "suite": "Control",
            "sku": "Control",
            "totalLicenses": 50,
            "unlimitedExpiration": True,
            "unlimitedLicenses": True,
            "externalId": "ext-123",
        })
        site = site_repo.get(sid)
        assert site.name == "All fields"
        assert site.siteType == "Trial"
        assert site.unlimitedExpiration is True
        assert site.externalId == "ext-123"


# ── reactivate_site ─────────────────────────────────────────────────────────


class TestReactivateSite:
    """Tests for the reactivate_site command."""

    def test_sets_state_to_active(self) -> None:
        sid = _first_site_id()
        # Expire first, then reactivate
        expire_site(sid)
        result = reactivate_site(sid)
        assert result is not None
        assert result["data"]["state"] == "active"

    def test_clears_expiration(self) -> None:
        sid = _first_site_id()
        expire_site(sid)
        reactivate_site(sid)
        assert site_repo.get(sid).expiration is None

    def test_updates_timestamp(self) -> None:
        sid = _first_site_id()
        old_ts = site_repo.get(sid).updatedAt
        reactivate_site(sid)
        assert site_repo.get(sid).updatedAt >= old_ts

    def test_nonexistent_returns_none(self) -> None:
        result = reactivate_site("does-not-exist")
        assert result is None


# ── expire_site ─────────────────────────────────────────────────────────────


class TestExpireSite:
    """Tests for the expire_site command."""

    def test_sets_state_to_expired(self) -> None:
        sid = _first_site_id()
        result = expire_site(sid)
        assert result is not None
        assert result["data"]["state"] == "expired"

    def test_sets_expiration_timestamp(self) -> None:
        sid = _first_site_id()
        expire_site(sid)
        assert site_repo.get(sid).expiration is not None

    def test_updates_updated_at(self) -> None:
        sid = _first_site_id()
        old_ts = site_repo.get(sid).updatedAt
        expire_site(sid)
        assert site_repo.get(sid).updatedAt >= old_ts

    def test_nonexistent_returns_none(self) -> None:
        result = expire_site("does-not-exist")
        assert result is None


# ── delete_site ─────────────────────────────────────────────────────────────


class TestDeleteSite:
    """Tests for the delete_site command."""

    def test_deletes_non_default_site(self) -> None:
        sid = _non_default_site_id()
        result = delete_site(sid)
        assert result is not None
        assert result["data"]["success"] is True

    def test_site_removed_from_repo(self) -> None:
        sid = _non_default_site_id()
        delete_site(sid)
        assert site_repo.get(sid) is None

    def test_refuses_to_delete_default_site(self) -> None:
        sid = _default_site_id()
        result = delete_site(sid)
        assert result is not None
        assert result.get("error") == "default"
        # Site should still exist
        assert site_repo.get(sid) is not None

    def test_nonexistent_site_returns_none(self) -> None:
        result = delete_site("does-not-exist")
        assert result is None
