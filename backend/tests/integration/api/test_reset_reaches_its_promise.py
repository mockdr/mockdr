"""A reset must reach the state the API serves back.

`POST /_dev/reset` promises the initial state.  HEC's acknowledgement ids
are per channel and monotonic, and the webhook delivery log is a bounded
deque — neither lives in the store `generate_all` clears, so both used to
survive a reset.  A client that reset between scenarios was handed ack ids
that carried on from the previous one, and `/collector/ack` answered `true`
for ids issued before the reset.
"""
from __future__ import annotations

import time
import uuid

import pytest
from fastapi.testclient import TestClient

HEC = {"Authorization": "Splunk 11111111-1111-1111-1111-111111111111"}
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _post_event(client: TestClient, channel: str) -> int:
    resp = client.post(
        "/splunk/services/collector/event",
        headers={**HEC, "X-Splunk-Request-Channel": channel},
        params={"useACK": "1"},
        json={"event": "reset probe"},
    )
    assert resp.status_code == 200, resp.text
    return int(resp.json()["ackId"])


class TestResetReachesHecAcks:
    def test_ack_ids_start_over_after_a_reset(self, client: TestClient) -> None:
        channel = str(uuid.uuid4())
        first = _post_event(client, channel)
        second = _post_event(client, channel)
        assert (first, second) == (0, 1), "ack ids are monotonic per channel"

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        # Same channel, fresh mock: the count starts at 0 again, as it does on
        # a channel that has never been used.
        assert _post_event(client, channel) == 0

    def test_an_ack_from_before_the_reset_is_not_acknowledged(
        self, client: TestClient,
    ) -> None:
        channel = str(uuid.uuid4())
        stale = _post_event(client, channel)

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        resp = client.post(
            "/splunk/services/collector/ack",
            headers={**HEC, "X-Splunk-Request-Channel": channel},
            json={"acks": [stale]},
        )
        # The channel is unknown again, so the token's own `use_ack` decides,
        # and this one does not have it: code 14, exactly what a channel that
        # was never used gets.  Before the reset reached this state the answer
        # was 200 `{"acks": {"0": true}}` — acknowledging an event the reset
        # had thrown away.
        assert resp.status_code == 400, resp.text
        assert resp.json() == {"text": "ACK is disabled", "code": 14}


class TestResetReachesTheWebhookDeliveryLog:
    """The other state `generate_all` cannot reach, served by `_dev`."""

    def test_deliveries_from_before_the_reset_are_gone(
        self, client: TestClient,
    ) -> None:
        from application.webhooks.delivery_log import DeliveryEntry, record

        record(DeliveryEntry(
            subscription_id="wh-reset-probe", event_type="threat.updated",
            status="success", attempt=1, timestamp="2026-01-01T00:00:00Z",
        ))
        before = client.get("/web/api/v2.1/_dev/webhooks/deliveries", headers=ADMIN)
        assert before.status_code == 200
        assert any(e["subscriptionId" if "subscriptionId" in e else "subscription_id"]
                   == "wh-reset-probe" for e in before.json()["data"])

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        after = client.get("/web/api/v2.1/_dev/webhooks/deliveries", headers=ADMIN)
        assert after.status_code == 200
        assert after.json()["data"] == []


class TestResetStopsARunningPlaybook:
    """A playbook started before a reset must not write into the fresh seed.

    The executor fetched the target agent once, before its first delay, and
    a later step saved that object back — with delays of up to 20 s in the
    built-in playbooks. `reset` never cancelled the run, so the agent as it
    stood before the reset (plus the step's change) reappeared in the store
    the reset had just rebuilt.
    """

    _PLAYBOOK = {
        "id": "reset-probe",
        "steps": [{
            "stepId": "late", "action": "agent_state", "delayMs": 600,
            "infected": True, "activeThreats": 7, "networkStatus": "disconnected",
        }],
    }

    def _start(self) -> tuple[str, tuple[object, ...]]:
        from application.playbook import executor
        from repository.agent_repo import agent_repo

        agent = agent_repo.list_all()[0]
        seeded = (agent.infected, agent.activeThreats, agent.networkStatus)
        executor.start(self._PLAYBOOK, agent.id)
        return agent.id, seeded

    @staticmethod
    def _state_after_the_step(agent_id: str) -> tuple[object, ...]:
        from repository.agent_repo import agent_repo

        time.sleep(1.0)  # past the step's delay
        agent = agent_repo.get(agent_id)
        assert agent is not None
        return (agent.infected, agent.activeThreats, agent.networkStatus)

    def test_the_reset_endpoint_stops_it(self, client: TestClient) -> None:
        from application.playbook._run_state import get_run

        agent_id, seeded = self._start()
        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        assert self._state_after_the_step(agent_id) == seeded
        run = get_run()
        assert run is not None and run.status == "cancelled"

    def test_a_reseed_stops_it_too(self) -> None:
        """The suite's per-test seed is the same boundary as a reset."""
        from infrastructure.seed import generate_all

        agent_id, seeded = self._start()
        generate_all()

        assert self._state_after_the_step(agent_id) == seeded


def _entra_token(client: TestClient, path: str, client_id: str, secret: str,
                 scope: str) -> dict[str, str]:
    resp = client.post(path, data={
        "client_id": client_id, "client_secret": secret,
        "grant_type": "client_credentials", "scope": scope,
    })
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _cs(client: TestClient) -> dict[str, str]:
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
    })
    assert resp.status_code in (200, 201), resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _mde(client: TestClient) -> dict[str, str]:
    return _entra_token(
        client, "/mde/oauth2/v2.0/token", "mde-mock-admin-client",
        "mde-mock-admin-secret", "https://api.securitycenter.microsoft.com/.default")


def _graph(client: TestClient) -> dict[str, str]:
    return _entra_token(
        client, "/graph/oauth2/v2.0/token", "graph-mock-admin-client",
        "graph-mock-admin-secret", "https://graph.microsoft.com/.default")


def _sentinel(client: TestClient) -> dict[str, str]:
    return _entra_token(
        client, "/sentinel/oauth2/v2.0/token", "sentinel-mock-client-id",
        "sentinel-mock-client-secret", "https://management.azure.com/.default")


def _splunk(client: TestClient) -> dict[str, str]:
    resp = client.post("/splunk/services/auth/login", params={"output_mode": "json"},
                       data={"username": "admin", "password": "mockdr-admin"})
    assert resp.status_code == 200, resp.text
    return {"Authorization": f"Splunk {resp.json()['sessionKey']}"}


_SENTINEL_WS = (
    "/sentinel/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


class TestResetKeepsIssuedCredentials:
    """A token or session issued before a reset still authenticates after it.

    ADR-013's pattern is a session-scoped server with ``reset()`` between
    tests, and the vendors' SDKs cache what they were issued — falconpy and
    MSAL their bearer token until it expires, splunklib its session key. The
    reset emptied every token and session collection, so each of those
    clients got a 401 on its first call after the first reset: a failure no
    real tenant produces, and one a test could only survive by knowing the
    mock's internals.
    """

    @pytest.mark.parametrize(("issue", "probe"), [
        (_cs, "/cs/devices/queries/devices/v1"),
        (_mde, "/mde/api/machines"),
        (_graph, "/graph/v1.0/users"),
        (_sentinel, f"{_SENTINEL_WS}/alertRules?api-version=2024-03-01"),
        (_splunk, "/splunk/services/server/info"),
    ], ids=["crowdstrike", "defender", "graph", "sentinel", "splunk"])
    def test_a_credential_survives_the_reset(
        self, client: TestClient, issue: object, probe: str,
    ) -> None:
        headers = issue(client)  # type: ignore[operator]
        assert client.get(probe, headers=headers).status_code == 200

        assert client.post("/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

        assert client.get(probe, headers=headers).status_code == 200

    def test_a_reseed_still_starts_with_nobody_signed_in(
        self, client: TestClient,
    ) -> None:
        """The suite's per-test seed and a cold start keep isolating tokens."""
        from infrastructure.seed import generate_all

        headers = _cs(client)
        generate_all()
        assert client.get(
            "/cs/devices/queries/devices/v1", headers=headers).status_code == 401


class TestResetTurnsFaultInjectionOff:
    """Fault injection is a test's chaos, not the product's — a reset ends it.

    It lived outside the store and the reset never touched it, so a test
    that set `errorRate: 1.0` and reset afterwards left every later test in
    the same server answering with injected 500s.
    """

    def test_injected_errors_stop_after_a_reset(self, client: TestClient) -> None:
        from api.middleware.fault_injection import get_fault_config, reset_fault_config

        try:
            set_resp = client.post(
                "/web/api/v2.1/_dev/fault-injection", headers=ADMIN,
                json={"errorRate": 1.0, "errorStatus": 503},
            )
            assert set_resp.status_code == 200
            assert client.get(
                "/web/api/v2.1/agents", headers=ADMIN).status_code == 503

            assert client.post(
                "/web/api/v2.1/_dev/reset", headers=ADMIN).status_code == 200

            assert get_fault_config().error_rate == 0.0
            assert client.get(
                "/web/api/v2.1/agents", headers=ADMIN).status_code == 200
        finally:
            reset_fault_config()
