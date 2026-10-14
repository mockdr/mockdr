"""Serving a request must not move what the next scenario picks.

``generate_all`` seeds the module-level ``random`` for the seed data, and
request handlers went on drawing from it: fault injection's jitter and error
roll, the XDR exclusion's modification time (a fresh draw on every request),
and every dev scenario. So which agents ``mass_infection`` hit after a reset
depended on what had been served since — a test asserting on the scenario's
effect passed on its own and failed after another one ran.
"""
from __future__ import annotations

import hashlib
import random
import secrets
import time

from fastapi.testclient import TestClient

ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
_DEV = "/web/api/v2.1/_dev"


def _infected_by(client: TestClient, scenario: str) -> set[str]:
    from repository.agent_repo import agent_repo

    before = {a.id for a in agent_repo.list_all() if a.isInfected}
    resp = client.post(f"{_DEV}/scenario", headers=ADMIN, json={"scenario": scenario})
    assert resp.status_code == 200, resp.text
    return {a.id for a in agent_repo.list_all() if a.isInfected} - before


class TestScenarioTargetsDoNotDependOnHistory:
    """The first run of a scenario after a reset hits the same agents."""

    def test_unrelated_draws_do_not_change_the_targets(self, client: TestClient) -> None:
        client.post(f"{_DEV}/reset", headers=ADMIN)
        first = _infected_by(client, "mass_infection")

        client.post(f"{_DEV}/reset", headers=ADMIN)
        # Whatever else drew from the shared stream in between.
        for _ in range(5):
            random.random()  # noqa: S311 - simulating unrelated draws
        second = _infected_by(client, "mass_infection")

        assert first and first == second

    def test_a_second_run_picks_its_own_reproducible_set(
        self, client: TestClient,
    ) -> None:
        """Not a frozen set: run two differs from run one, and repeats itself."""
        from repository.agent_repo import agent_repo

        def two_runs() -> list[list[str]]:
            client.post(f"{_DEV}/reset", headers=ADMIN)
            runs = []
            for _ in range(2):
                client.post(f"{_DEV}/scenario", headers=ADMIN,
                            json={"scenario": "agent_offline"})
                runs.append(sorted(
                    a.id for a in agent_repo.list_all()
                    if a.networkStatus == "disconnected"))
            return runs

        once, again = two_runs(), two_runs()
        assert once == again
        assert once[0] != once[1]


class TestRequestsLeaveTheSharedStreamAlone:
    """Fault injection draws from its own generator."""

    def test_fault_injection_does_not_draw_from_random(self, client: TestClient) -> None:
        from api.middleware.fault_injection import reset_fault_config

        try:
            client.post(f"{_DEV}/fault-injection", headers=ADMIN,
                        json={"errorRate": 0.5, "delayJitterMs": 1})
            state = random.getstate()
            for _ in range(10):
                client.get("/web/api/v2.1/sites", headers=ADMIN)
            assert random.getstate() == state
        finally:
            reset_fault_config()

    def test_a_configuration_fails_the_same_requests_every_time(
        self, client: TestClient,
    ) -> None:
        from api.middleware.fault_injection import reset_fault_config

        def pattern() -> list[int]:
            client.post(f"{_DEV}/fault-injection", headers=ADMIN, json={"errorRate": 0.5})
            return [client.get("/web/api/v2.1/sites", headers=ADMIN).status_code
                    for _ in range(12)]

        try:
            first, second = pattern(), pattern()
            assert first == second
            assert set(first) == {200, 500}
        finally:
            reset_fault_config()


def _xdr_headers() -> dict[str, str]:
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    digest = hashlib.sha256(("xdr-admin-secret" + nonce + timestamp).encode()).hexdigest()
    return {"x-xdr-auth-id": "1", "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp, "Authorization": digest}


class TestXdrExclusionTimeIsStable:
    """The canned exclusion's modification time drew anew on every request."""

    def test_two_reads_report_the_same_modification_time(
        self, client: TestClient,
    ) -> None:
        def modified() -> object:
            resp = client.post("/xdr/public_api/v1/alerts_exclusion/",
                               headers=_xdr_headers(), json={"request_data": {}})
            assert resp.status_code == 200, resp.text
            return resp.json()["reply"][0]["ALERT_WHITELIST_MODIFY_TIME"]

        first = modified()
        assert first == modified()
        assert 0 <= time.time() * 1000 - int(str(first)) <= 86_400_000
