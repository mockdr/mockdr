"""Integration tests for ARM ``api-version`` enforcement.

These use a plain TestClient rather than the ARM client fixture, because the
point is what happens when the parameter is *not* supplied.
"""
import pytest
from fastapi.testclient import TestClient

import main

SENTINEL_PREFIX = "/sentinel"

_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


@pytest.fixture()
def raw_client(fresh_seed: None) -> TestClient:
    """Client that adds nothing to the request, unlike the ARM SDK."""
    return TestClient(main.app)


def _auth(client: TestClient) -> dict[str, str]:
    """Return Sentinel Bearer headers."""
    resp = client.post(f"{SENTINEL_PREFIX}/oauth2/v2.0/token", data={
        "client_id": "sentinel-mock-client-id",
        "client_secret": "sentinel-mock-client-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestApiVersionRequired:
    """ARM refuses management-plane requests without ``api-version``."""

    def test_missing_api_version_returns_400(self, raw_client: TestClient) -> None:
        resp = raw_client.get(f"{SENTINEL_PREFIX}{_WS}/incidents", headers=_auth(raw_client))
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "MissingApiVersionParameter"

    def test_valid_api_version_is_served(self, raw_client: TestClient) -> None:
        resp = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents?api-version=2024-03-01",
            headers=_auth(raw_client),
        )
        assert resp.status_code == 200

    def test_preview_versions_are_served(self, raw_client: TestClient) -> None:
        """Preview versions ship constantly; they must not be rejected."""
        resp = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents?api-version=2025-06-01-preview",
            headers=_auth(raw_client),
        )
        assert resp.status_code == 200

    @pytest.mark.parametrize("value", ["v1", "2024", "latest", "1999-01-01", "2024-13-45"])
    def test_implausible_versions_return_400(
        self, raw_client: TestClient, value: str,
    ) -> None:
        resp = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents?api-version={value}",
            headers=_auth(raw_client),
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "InvalidApiVersionParameter"

    def test_log_analytics_query_needs_no_api_version(
        self, raw_client: TestClient,
    ) -> None:
        """The query endpoint is api.loganalytics.io, not ARM."""
        resp = raw_client.post(
            f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query",
            headers=_auth(raw_client),
            json={"query": "SecurityAlert | take 1"},
        )
        assert resp.status_code == 200

    def test_token_endpoint_needs_no_api_version(self, raw_client: TestClient) -> None:
        """The Entra token endpoint is not an ARM resource."""
        resp = raw_client.post(f"{SENTINEL_PREFIX}/oauth2/v2.0/token", data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
        })
        assert resp.status_code == 200


class TestSkipTokenPagination:
    """ARM pagination: bad tokens are rejected, nextLink is followable."""

    def test_garbage_skip_token_returns_400(self, raw_client: TestClient) -> None:
        """A token this service never issued must not crash the request."""
        resp = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents?api-version=2024-03-01&$skipToken=abc",
            headers=_auth(raw_client),
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "InvalidSkipToken"

    def test_negative_skip_token_returns_400(self, raw_client: TestClient) -> None:
        resp = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents?api-version=2024-03-01&$skipToken=-5",
            headers=_auth(raw_client),
        )
        assert resp.status_code == 400

    def test_next_link_is_absolute_and_followable(self, raw_client: TestClient) -> None:
        """ARM returns a URL the client can call verbatim."""
        headers = _auth(raw_client)
        first = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents?api-version=2024-03-01&$top=2",
            headers=headers,
        )
        next_link = first.json().get("nextLink")
        assert next_link, "expected a nextLink for a paged result"
        assert next_link.startswith("http")
        assert "api-version=2024-03-01" in next_link

        second = raw_client.get(next_link, headers=headers)
        assert second.status_code == 200
        first_ids = {i["name"] for i in first.json()["value"]}
        second_ids = {i["name"] for i in second.json()["value"]}
        assert not (first_ids & second_ids), "pages must not overlap"

    def test_next_link_preserves_filters(self, raw_client: TestClient) -> None:
        """Following the link must not silently drop the query."""
        resp = raw_client.get(
            f"{SENTINEL_PREFIX}{_WS}/incidents"
            f"?api-version=2024-03-01&$top=1&$orderby=properties/createdTimeUtc",
            headers=_auth(raw_client),
        )
        next_link = resp.json().get("nextLink", "")
        assert "%24orderby" in next_link or "$orderby" in next_link
