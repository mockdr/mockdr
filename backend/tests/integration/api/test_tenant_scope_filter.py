"""Tenant-scoping regressions for the SentinelOne list endpoints.

``TenantScopeMiddleware`` confines a non-admin caller by appending
``accountIds=<their account>`` to the query string, and each endpoint declares
a matching ``FilterSpec``. But six routes never declared ``accountIds`` as a
parameter, so FastAPI dropped it before the handler built its filter dict —
the scoping was inert and every caller saw the whole store.

These tests exercise the filter directly: a value that matches no account must
select nothing. If a route stops accepting the parameter, the count comes back
unfiltered and the test fails.
"""
import pytest
from fastapi.testclient import TestClient

PREFIX = "/web/api/v2.1"

# Every endpoint whose query layer declares a FilterSpec("accountIds", ...).
SCOPED_ENDPOINTS = [
    "agents",
    "threats",
    "groups",
    "users",
    "activities",
    "cloud-detection/alerts",
]


@pytest.mark.parametrize("endpoint", SCOPED_ENDPOINTS)
class TestAccountIdsIsHonoured:
    """``accountIds`` must reach the filter engine on every scoped endpoint."""

    def test_unknown_account_selects_nothing(
        self, client: TestClient, auth_headers: dict, endpoint: str,
    ) -> None:
        body = client.get(
            f"{PREFIX}/{endpoint}?accountIds=no-such-account", headers=auth_headers,
        ).json()

        assert body["pagination"]["totalItems"] == 0, (
            f"{endpoint} ignored accountIds — tenant scoping is not enforced"
        )
        assert body["data"] == []

    def test_real_account_selects_records(
        self, client: TestClient, auth_headers: dict, endpoint: str,
    ) -> None:
        account_id = client.get(
            f"{PREFIX}/accounts", headers=auth_headers,
        ).json()["data"][0]["id"]

        body = client.get(
            f"{PREFIX}/{endpoint}?accountIds={account_id}", headers=auth_headers,
        ).json()

        assert body["pagination"]["totalItems"] > 0, (
            f"{endpoint} filtered out its own account's records"
        )
