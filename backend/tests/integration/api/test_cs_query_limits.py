"""A page size Falcon accepts is one the mock accepts.

The query routes capped ``limit`` well below what gofalcon documents, so a
client asking for a page the product serves met a 400 here — and a CI run
against the mock failed on a request that works in production. The bounds
now come from gofalcon's parameter documentation, one file per route:

    query_devices_by_filter_parameters.go           [1-5000]
    query_devices_by_filter_scroll_parameters.go    [1-10000]
    combined_hidden_devices_by_filter_parameters.go [1-10000]
    query_v2_parameters.go (alerts)                 default 100, max 10000
    query_combined_host_groups_parameters.go        [1-5000]
    query_host_groups_parameters.go                 [1-5000]
    query_group_members_parameters.go               [1-5000]
    query_combined_group_members_parameters.go      [1-5000]
    queries_cases_get_v1_parameters.go              default 100, max 10000
    combined_applications_parameters.go             Min 1, Max 1000

``/devices/queries/devices/v1`` also has a window: offset plus limit must stay
under 10,000, past which Falcon sends a client to the scroll route. falconpy
discussion #536 records the refusal word for word:
``{'code': 400, 'message': 'limit + offset must be less than 10000'}``.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

#: (path, extra params, the largest documented limit)
DOCUMENTED_MAXIMA = [
    ("/cs/devices/queries/devices/v1", {}, 5000),
    ("/cs/devices/queries/devices-scroll/v1", {}, 10000),
    ("/cs/devices/combined/devices-hidden/v1", {}, 10000),
    ("/cs/alerts/queries/alerts/v2", {}, 10000),
    ("/cs/devices/combined/host-groups/v1", {}, 5000),
    ("/cs/devices/queries/host-groups/v1", {}, 5000),
    ("/cs/devices/queries/host-group-members/v1", {"id": "x"}, 5000),
    ("/cs/devices/combined/host-group-members/v1", {"id": "x"}, 5000),
    ("/cs/cases/queries/cases/v1", {}, 10000),
    ("/cs/discover/combined/applications/v1", {}, 1000),
]


def _cs_auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestDocumentedPageSizes:
    """The largest page gofalcon documents is served, one more is refused."""

    @pytest.mark.parametrize(("path", "extra", "maximum"), DOCUMENTED_MAXIMA)
    def test_the_documented_maximum_is_accepted(
        self, client: TestClient, path: str, extra: dict, maximum: int,
    ) -> None:
        resp = client.get(path, headers=_cs_auth(client),
                          params={**extra, "limit": maximum})
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize(("path", "extra", "maximum"), DOCUMENTED_MAXIMA)
    def test_one_past_the_maximum_is_refused(
        self, client: TestClient, path: str, extra: dict, maximum: int,
    ) -> None:
        resp = client.get(path, headers=_cs_auth(client),
                          params={**extra, "limit": maximum + 1})
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == 400


class TestDeviceQueryWindow:
    """``/devices/queries/devices/v1`` pages only the first 10,000 hosts."""

    def test_offset_plus_limit_at_the_window_is_refused(self, client: TestClient) -> None:
        resp = client.get("/cs/devices/queries/devices/v1", headers=_cs_auth(client),
                          params={"offset": 10000, "limit": 1})
        assert resp.status_code == 400
        assert resp.json()["errors"] == [
            {"code": 400, "message": "limit + offset must be less than 10000"},
        ]

    def test_the_last_page_inside_the_window_is_served(self, client: TestClient) -> None:
        resp = client.get("/cs/devices/queries/devices/v1", headers=_cs_auth(client),
                          params={"offset": 9998, "limit": 1})
        assert resp.status_code == 200
        assert resp.json()["resources"] == []
