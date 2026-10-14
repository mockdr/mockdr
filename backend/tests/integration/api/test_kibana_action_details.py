"""Kibana's response actions answer ``ActionDetails``, and a client can wait on one.

The documented way to run a response action is to POST it and poll ``GET
/api/endpoint/action/{id}`` until ``data.isCompleted``. Kibana answers both
with ``{data: ActionDetails}`` -- isolate and unisolate also repeat the id as
a top-level ``action`` for older clients -- and the list with
``ActionListApiResponse`` (security solution ``common/endpoint/types/
actions.ts``; Kibana API reference, "Isolate an endpoint", "Get action
details", "Get response actions list"). The mock answered its own storage
record: ``agent_id``, ``action``, ``started_at``, no ``data``. A client
written to the reference -- the workflow below, driven with ``requests``
-- read ``data`` off the isolate answer and failed before it could poll.
"""
from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient

from application.es_endpoints import commands as endpoint_commands

KBN = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
       "kbn-xsrf": "true"}

#: ``ActionDetails``' members, as the reference lists them.
DETAILS = {"id", "agents", "agentType", "hosts", "command", "isExpired", "isCompleted",
           "wasSuccessful", "errors", "startedAt", "status", "outputs", "agentState",
           "createdBy", "comment", "parameters"}


def _agent(client: TestClient) -> tuple[str, str]:
    listed = client.get("/kibana/api/endpoint/metadata", headers=KBN).json()
    meta = listed["data"][0]["metadata"]
    return str(meta["agent"]["id"]), str(meta["host"]["hostname"])


class TestIsolateThenPoll:
    """POST the action, then poll its details until it completes."""

    def test_the_documented_workflow(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent, hostname = _agent(client)
        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 3600.0)
        created = client.post("/kibana/api/endpoint/action/isolate", headers=KBN,
                              json={"endpoint_ids": [agent], "comment": "smoke"})
        assert created.status_code == 200, created.text
        body = created.json()
        assert set(body) == {"action", "data"}
        data = body["data"]
        assert DETAILS <= set(data)
        assert body["action"] == data["id"]
        assert data["agents"] == [agent]
        assert data["hosts"] == {agent: {"name": hostname}}
        assert data["command"] == "isolate"
        assert data["comment"] == "smoke"
        assert (data["status"], data["isCompleted"], data["wasSuccessful"]) == (
            "pending", False, False)
        assert data["agentState"][agent]["isCompleted"] is False

        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 0.0)
        polled = client.get(f"/kibana/api/endpoint/action/{data['id']}", headers=KBN)
        assert polled.status_code == 200, polled.text
        done = polled.json()["data"]
        assert (done["status"], done["isCompleted"], done["wasSuccessful"]) == (
            "successful", True, True)
        assert done["completedAt"]
        assert done["agentState"][agent]["completedAt"] == done["completedAt"]

    def test_other_actions_carry_no_legacy_property(self, client: TestClient) -> None:
        agent, _ = _agent(client)
        created = client.post("/kibana/api/endpoint/action/running_procs", headers=KBN,
                              json={"endpoint_ids": [agent]})
        assert created.status_code == 200, created.text
        assert set(created.json()) == {"data"}
        assert created.json()["data"]["command"] == "running-processes"


class TestTheList:
    """``ActionListApiResponse``, a page at a time, newest first."""

    def test_pages_of_details(self, client: TestClient) -> None:
        agent, _ = _agent(client)
        ids = [client.post("/kibana/api/endpoint/action/scan", headers=KBN,
                           json={"endpoint_ids": [agent],
                                 "parameters": {"path": f"/tmp/{n}"}}).json()["data"]["id"]
               for n in range(3)]
        first = client.get("/kibana/api/endpoint/action", headers=KBN,
                           params={"agentIds": agent, "pageSize": 2}).json()
        assert (first["page"], first["pageSize"]) == (1, 2)
        assert first["total"] >= 3
        assert len(first["data"]) == 2
        assert all(DETAILS <= set(a) for a in first["data"])
        second = client.get("/kibana/api/endpoint/action", headers=KBN,
                            params={"agentIds": agent, "pageSize": 2, "page": 2}).json()
        listed = [a["id"] for a in first["data"] + second["data"]]
        assert len(set(listed)) == len(listed)
        assert listed[0] == ids[-1], "newest first"

    def test_the_default_page_is_ten(self, client: TestClient) -> None:
        body = client.get("/kibana/api/endpoint/action", headers=KBN).json()
        assert (body["page"], body["pageSize"]) == (1, 10)
        assert (body["startDate"], body["endDate"]) == ("now-24h/h", "now")
        assert len(body["data"]) <= 10

    def test_the_window_selects_by_start(self, client: TestClient) -> None:
        agent, _ = _agent(client)
        client.post("/kibana/api/endpoint/action/isolate", headers=KBN,
                    json={"endpoint_ids": [agent]})
        inside = client.get("/kibana/api/endpoint/action", headers=KBN,
                            params={"agentIds": agent, "startDate": "now-1h"}).json()
        before = client.get("/kibana/api/endpoint/action", headers=KBN,
                            params={"agentIds": agent, "startDate": "now-2d",
                                    "endDate": "now-1d"}).json()
        assert inside["total"] >= 1
        assert before["total"] == 0

    def test_an_unreadable_date_is_400(self, client: TestClient) -> None:
        response = client.get("/kibana/api/endpoint/action", headers=KBN,
                              params={"startDate": "yesterday-ish"})
        assert response.status_code == 400
