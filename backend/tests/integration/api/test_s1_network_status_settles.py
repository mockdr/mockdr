"""Connect and disconnect are in transit until the agent acknowledges.

``networkStatus`` is enumerated ``connected``, ``disconnected``,
``connecting``, ``disconnecting`` (``agents.schemas_AgentViewSchema`` in the
2.1 swagger). The actions jumped straight to the final state, so the two
transitional values never occurred and a client that polls until the agent
is ``disconnected`` — or that reads ``disconnecting`` as "isolation asked
for, not yet in force" — was never exercised. A read straight after the
action now finds the agent in transit, and a read a moment later finds it
settled, as the Falcon mount's containment does.

The clock is held the way ``test_cs_hosts`` holds containment's: by moving
``application.settling.SETTLE_SECONDS``, so a loaded run cannot spend the
second between two calls.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _agent(client: TestClient, status: str) -> str:
    agents = client.get(f"{BASE}/agents", headers=S1,
                        params={"networkStatuses": status, "limit": 1}).json()["data"]
    return agents[0]["id"]


def _status(client: TestClient, agent_id: str) -> str:
    return client.get(f"{BASE}/agents", headers=S1,
                      params={"ids": agent_id}).json()["data"][0]["networkStatus"]


class TestInTransit:
    """Straight after the action the agent has not answered yet."""

    @pytest.mark.parametrize(("action", "start", "pending"), [
        ("disconnect", "connected", "disconnecting"),
        ("connect", "disconnected", "connecting"),
    ])
    def test_the_transitional_state_is_read(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
        action: str, start: str, pending: str,
    ) -> None:
        monkeypatch.setattr("application.settling.SETTLE_SECONDS", 3600.0)
        agent_id = _agent(client, start)
        resp = client.post(f"{BASE}/agents/actions/{action}", headers=S1,
                           json={"filter": {"ids": [agent_id]}})
        assert resp.json()["data"]["affected"] == 1
        assert _status(client, agent_id) == pending

    def test_a_filter_finds_the_agent_in_transit(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr("application.settling.SETTLE_SECONDS", 3600.0)
        agent_id = _agent(client, "connected")
        client.post(f"{BASE}/agents/actions/disconnect", headers=S1,
                    json={"filter": {"ids": [agent_id]}})
        found = client.get(f"{BASE}/agents", headers=S1,
                           params={"networkStatuses": "disconnecting"}).json()["data"]
        # The seed holds agents that never acknowledged as well.
        assert agent_id in {a["id"] for a in found}


class TestSettled:
    """Once the agent has acknowledged, the final state is read."""

    @pytest.mark.parametrize(("action", "start", "final"), [
        ("disconnect", "connected", "disconnected"),
        ("connect", "disconnected", "connected"),
    ])
    def test_the_final_state_follows(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
        action: str, start: str, final: str,
    ) -> None:
        agent_id = _agent(client, start)
        client.post(f"{BASE}/agents/actions/{action}", headers=S1,
                    json={"filter": {"ids": [agent_id]}})
        # The acknowledgement has arrived: any wait at all is long enough.
        monkeypatch.setattr("application.settling.SETTLE_SECONDS", -1.0)
        assert _status(client, agent_id) == final

    def test_the_count_sees_the_settled_state(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        before = client.get(f"{BASE}/agents/count", headers=S1,
                            params={"networkStatuses": "disconnected"}).json()["data"]["total"]
        agent_id = _agent(client, "connected")
        client.post(f"{BASE}/agents/actions/disconnect", headers=S1,
                    json={"filter": {"ids": [agent_id]}})
        monkeypatch.setattr("application.settling.SETTLE_SECONDS", -1.0)
        after = client.get(f"{BASE}/agents/count", headers=S1,
                           params={"networkStatuses": "disconnected"}).json()["data"]["total"]
        assert after == before + 1
