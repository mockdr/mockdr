"""A number the request got wrong is the request's fault, not the server's.

`int(body.get(...))` with no guard raised out of four handlers, so a body
carrying `"abc"`, a dict, or `Infinity` where a number belongs came back
500. A 500 tells a client the server is broken and to retry the same body;
it will fail the same way for as long as it tries. A 400 tells it what is
actually true.

Python's JSON parser accepts `Infinity` and `1e400`, and `int()` of either
raises `OverflowError` — a third kind, which the guards that did exist did
not catch. `int(1e20)` is also a fine Python number and no kind of
Elasticsearch one: its bounds are Java ints, and 8.15 refuses anything past
2147483647 at parse time.

Measured on Elasticsearch 8.15, one body at a time against `_search`:

    {"size": "abc"}         400  For input string: "abc"
    {"size": 1e400}         400  Numeric value (1e400) out of range of int …
    {"size": 2147483648}    400  Numeric value (2147483648) out of range …
    {"size": 2147483647}    400  Result window is too large …
    {"size": -1}            400  [size] parameter cannot be negative, found [-1]
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ=",
    "content-type": "application/json",
}
S1_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)

#: (raw body, the start of the reason 8.15 gives)
ES_SIZES = [
    (b'{"size": "abc"}', 'For input string: "abc"'),
    (b'{"size": Infinity}', "Numeric value ("),
    (b'{"size": 1e400}', "Numeric value ("),
    (b'{"size": 2147483648}', "Numeric value (2147483648) out of range of int"),
    (b'{"size": 100000000000}', "Numeric value (100000000000) out of range of int"),
    (b'{"size": -1}', "[size] parameter cannot be negative, found [-1]"),
    (b'{"size": 2147483647}', "all shards failed"),
]


class TestElasticsearchSize:
    @pytest.mark.parametrize(("raw", "reason"), ES_SIZES)
    def test_it_is_a_400_and_says_why(
        self, client: TestClient, raw: bytes, reason: str,
    ) -> None:
        resp = client.post("/elastic/_search", headers=ES_AUTH, content=raw)
        assert resp.status_code == 400, resp.text
        assert str(resp.json()["error"]["reason"]).startswith(reason)

    def test_a_size_inside_the_bounds_still_searches(
        self, client: TestClient,
    ) -> None:
        resp = client.post("/elastic/_search", headers=ES_AUTH, content=b'{"size": 5}')
        assert resp.status_code == 200, resp.text


class TestSentinelConfidenceBounds:
    def _headers(self, client: TestClient) -> dict[str, str]:
        resp = client.post("/sentinel/oauth2/v2.0/token", data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
            "scope": "https://management.azure.com/.default"})
        return {"Authorization": f"Bearer {resp.json()['access_token']}",
                "content-type": "application/json"}

    @pytest.mark.parametrize("raw", [
        b'{"minConfidence": "abc"}',
        b'{"pageSize": "many"}',
        b'{"minConfidence": {"x": 1}}',
        b'{"pageSize": Infinity}',
        b'{"minConfidence": 1e999}',
    ])
    def test_a_bound_that_is_not_a_number(
        self, client: TestClient, raw: bytes,
    ) -> None:
        resp = client.post(
            f"/sentinel{_WS}/threatIntelligence/main/queryIndicators",
            headers=self._headers(client), params={"api-version": "2024-03-01"},
            content=raw)
        assert resp.status_code == 400, resp.text
        assert resp.json()["error"]["code"] == "BadRequest"

    def test_a_query_with_real_bounds_still_answers(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            f"/sentinel{_WS}/threatIntelligence/main/queryIndicators",
            headers=self._headers(client), params={"api-version": "2024-03-01"},
            json={"minConfidence": 0, "maxConfidence": 100, "pageSize": 5})
        assert resp.status_code == 200, resp.text
        assert isinstance(resp.json()["value"], list)


class TestSentinelOneLicenceCount:
    @pytest.mark.parametrize("licences", ["abc", {"x": 1}, [1], True])
    def test_a_licence_count_that_is_not_a_number(
        self, client: TestClient, licences: object,
    ) -> None:
        resp = client.post("/web/api/v2.1/sites", headers=S1_AUTH, json={
            "data": {"name": "probe", "totalLicenses": licences}})
        assert resp.status_code == 400, resp.text
        assert resp.json()["errors"][0]["detail"] == (
            "data.totalLicenses must be a number")

    def test_a_real_licence_count_still_creates_the_site(
        self, client: TestClient,
    ) -> None:
        resp = client.post("/web/api/v2.1/sites", headers=S1_AUTH, json={
            "data": {"name": "probe-ok", "totalLicenses": 25}})
        assert resp.status_code in (200, 201), resp.text
        assert resp.json()["data"]["totalLicenses"] == 25
