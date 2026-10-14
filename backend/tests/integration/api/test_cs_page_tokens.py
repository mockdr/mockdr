"""Falcon's continuation tokens are opaque, and ``total`` holds on every page.

Three defects in the routes that page by token rather than by number:

* The devices-scroll route reported ``meta.pagination.total`` as 0 on every
  page after the first. falconpy's own scrolling sample
  (``samples/hosts/sensor_versions_by_hostname_scrolling.py``) re-reads
  ``total`` from each response as its loop bound, so it stopped after the
  second page whatever the size of the fleet. Discover's ``after`` paging
  did the same.
* The tokens were the bare index (``"500"``) and were read back with
  ``int()``, so a token the mock had not minted — a real one replayed, a
  truncated one — was a 500. It is a 400 in Falcon's ``errors`` envelope now.
* ``/iocs/combined/indicator/v1`` did not declare ``after`` at all, though
  gofalcon documents it (indicator_combined_v1_parameters.go) and the
  response model carries ``meta.pagination.after``: a client paging by
  token got the first page back on every call.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestDeviceScroll:
    """The scroll walk falconpy's sample does reaches every host."""

    def test_the_sample_loop_sees_every_host(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # The sample's loop, verbatim in shape: page while position < total,
        # with total re-read from every response.
        offset, total, position, seen = None, 1, 0, []
        while position < total:
            params: dict = {"limit": 7}
            if offset:
                params["offset"] = offset
            body = client.get("/cs/devices/queries/devices-scroll/v1",
                              headers=headers, params=params).json()
            offset = body["meta"]["pagination"]["offset"]
            total = body["meta"]["pagination"]["total"]
            seen.extend(body["resources"])
            position += 7
        assert len(seen) == 60
        assert len(set(seen)) == 60

    def test_total_is_the_same_on_every_page(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        first = client.get("/cs/devices/queries/devices-scroll/v1", headers=headers,
                           params={"limit": 10}).json()
        second = client.get("/cs/devices/queries/devices-scroll/v1", headers=headers,
                            params={"limit": 10,
                                    "offset": first["meta"]["pagination"]["offset"]}).json()
        assert second["meta"]["pagination"]["total"] == first["meta"]["pagination"]["total"] == 60

    def test_the_token_is_not_a_bare_index(self, client: TestClient) -> None:
        body = client.get("/cs/devices/queries/devices-scroll/v1",
                          headers=_cs_auth(client), params={"limit": 10}).json()
        assert not body["meta"]["pagination"]["offset"].isdigit()

    @pytest.mark.parametrize("token", ["abc", "10", "%%%", "bW9ja2RyLWNzOi0x"])
    def test_a_token_the_mock_did_not_issue_is_a_400(
        self, client: TestClient, token: str,
    ) -> None:
        resp = client.get("/cs/devices/queries/devices-scroll/v1",
                          headers=_cs_auth(client), params={"offset": token})
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == 400


class TestIocAfter:
    """``after`` walks the IOC collection to its end."""

    def test_after_walks_every_indicator_once(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        whole = client.get("/cs/iocs/combined/indicator/v1", headers=headers,
                           params={"limit": 500}).json()
        expected = whole["meta"]["pagination"]["total"]
        assert expected > 3
        seen: list[str] = []
        after = None
        for _ in range(expected + 1):
            params: dict = {"limit": 3}
            if after:
                params["after"] = after
            body = client.get("/cs/iocs/combined/indicator/v1", headers=headers,
                              params=params).json()
            seen.extend(r["id"] for r in body["resources"])
            after = body["meta"]["pagination"]["after"]
            if not after:
                break
        assert len(seen) == expected
        assert len(set(seen)) == expected

    def test_a_foreign_after_token_is_a_400(self, client: TestClient) -> None:
        resp = client.get("/cs/iocs/combined/indicator/v1", headers=_cs_auth(client),
                          params={"after": "not-a-token"})
        assert resp.status_code == 400


class TestDiscoverAfter:
    """Discover's ``after`` paging keeps its total and refuses foreign tokens."""

    def test_total_is_the_same_on_the_second_page(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        first = client.get("/cs/discover/combined/applications/v1", headers=headers,
                           params={"limit": 5}).json()
        after = first["meta"]["pagination"]["after"]
        assert after
        second = client.get("/cs/discover/combined/applications/v1", headers=headers,
                            params={"limit": 5, "after": after}).json()
        assert second["meta"]["pagination"]["total"] == first["meta"]["pagination"]["total"]
        assert second["resources"] != first["resources"]

    def test_a_foreign_after_token_is_a_400(self, client: TestClient) -> None:
        resp = client.get("/cs/discover/combined/applications/v1",
                          headers=_cs_auth(client), params={"after": "zzz"})
        assert resp.status_code == 400
