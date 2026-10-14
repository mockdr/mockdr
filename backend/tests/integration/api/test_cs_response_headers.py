"""Every Falcon answer carries its trace id and its rate-limit budget.

gofalcon declares ``X-CS-TRACEID``, ``X-RateLimit-Limit`` and
``X-RateLimit-Remaining`` on every response (each ``*_responses.go`` hydrates
the three), and captured Falcon traffic carries them on every answer,
successes and refusals alike:

    X-Cs-Traceid: d3f778c2-5e4a-4dca-a7ed-b91a3217693a
    X-Ratelimit-Limit: 6000
    X-Ratelimit-Remaining: 5927            (falconpy issue #1209)

    X-Cs-Traceid=62e63c48-…, X-Ratelimit-Limit=300, X-Ratelimit-Remaining=297
    … trace_id=62e63c48-…                  (psfalcon issue #442, /oauth2/revoke)

The mount never sent the trace id or the limit, and sent ``Remaining`` only
while the dev limiter was switched on — so a client that paces itself on the
budget, or logs the trace id for a support case, read nothing. The limit is
6000 for an authenticated API client and 300 where no token is presented
(the token routes), the trace id is the body's ``meta.trace_id``, and the
dev limiter, when on, still sets and enforces its own budget.
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


class TestFalconHeadersOnEveryAnswer:
    """The three declared headers, with the limiter off."""

    def test_an_api_call_states_falcons_budget(self, client: TestClient) -> None:
        resp = client.get("/cs/devices/queries/devices/v1", headers=_cs_auth(client),
                          params={"limit": 1})
        assert resp.headers["x-ratelimit-limit"] == "6000"
        assert resp.headers["x-ratelimit-remaining"] == "5999"

    def test_the_budget_counts_down(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        seen = [
            int(client.get("/cs/devices/queries/devices/v1", headers=headers,
                           params={"limit": 1}).headers["x-ratelimit-remaining"])
            for _ in range(3)
        ]
        assert seen == [5999, 5998, 5997]

    def test_the_token_route_has_the_unauthenticated_budget(self, client: TestClient) -> None:
        resp = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        })
        assert resp.headers["x-ratelimit-limit"] == "300"
        assert int(resp.headers["x-ratelimit-remaining"]) < 300

    @pytest.mark.parametrize(("params", "status"), [
        ({"limit": 1}, 200),
        ({"limit": 999999}, 400),
    ])
    def test_the_trace_id_is_the_bodys(
        self, client: TestClient, params: dict, status: int,
    ) -> None:
        resp = client.get("/cs/devices/queries/devices/v1", headers=_cs_auth(client),
                          params=params)
        assert resp.status_code == status
        assert resp.headers["x-cs-traceid"] == resp.json()["meta"]["trace_id"]

    def test_a_refused_credential_carries_them_too(self, client: TestClient) -> None:
        resp = client.get("/cs/devices/queries/devices/v1")
        assert resp.status_code == 401
        assert resp.headers["x-cs-traceid"] == resp.json()["meta"]["trace_id"]
        assert resp.headers["x-ratelimit-limit"] == "300"

    def test_each_answer_has_its_own_trace_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = {
            client.get("/cs/devices/queries/devices/v1", headers=headers,
                       params={"limit": 1}).headers["x-cs-traceid"]
            for _ in range(3)
        }
        assert len(ids) == 3


class TestTheDevLimiterSetsTheBudget:
    """With throttling switched on, its rate is the one stated and enforced."""

    def test_limit_is_the_configured_rate(self, client: TestClient) -> None:
        client.post("/web/api/v2.1/_dev/rate-limit",
                    headers={"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
                    json={"enabled": True, "requestsPerMinute": 5})
        headers = _cs_auth(client)
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers,
                          params={"limit": 1})
        assert resp.headers["x-ratelimit-limit"] == "5"
        assert resp.headers["x-ratelimit-remaining"] == "4"
        for _ in range(4):
            client.get("/cs/devices/queries/devices/v1", headers=headers, params={"limit": 1})
        refused = client.get("/cs/devices/queries/devices/v1", headers=headers,
                             params={"limit": 1})
        assert refused.status_code == 429
        assert refused.headers["x-cs-traceid"] == refused.json()["meta"]["trace_id"]
        assert refused.headers["x-ratelimit-limit"] == "5"
