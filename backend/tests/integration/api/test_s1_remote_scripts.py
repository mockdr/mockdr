"""POST /remote-scripts/execute takes the body the swagger documents.

`data` carries the script, `filter` the agents, both required. The request
model declared only `data`, so `filter` was dropped before the handler saw
it and the documented call answered `400 A filter is required` -- the
shipped Postman and Bruno requests among them.
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
SCRIPT = {"scriptId": "script-001", "outputDestination": "SentinelCloud",
          "taskDescription": "Collect process list"}


def _agent_ids(client: TestClient, auth_headers: dict, n: int) -> list[str]:
    body = client.get(f"{BASE}/agents", params={"limit": n}, headers=auth_headers).json()
    return [a["id"] for a in body["data"]]


def test_the_documented_body_runs_on_the_agents_it_names(
    client: TestClient, auth_headers: dict,
) -> None:
    ids = _agent_ids(client, auth_headers, 2)
    resp = client.post(f"{BASE}/remote-scripts/execute", headers=auth_headers,
                       json={"data": SCRIPT, "filter": {"ids": ids}})
    assert resp.status_code == 200, resp.text
    assert resp.json()["data"]["affected"] == len(ids)


def test_without_a_filter_it_is_still_refused(client: TestClient, auth_headers: dict) -> None:
    resp = client.post(f"{BASE}/remote-scripts/execute", headers=auth_headers,
                       json={"data": SCRIPT})
    assert resp.status_code == 400
