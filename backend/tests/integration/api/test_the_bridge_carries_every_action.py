"""ADR-009 promises the SIEM sees an EDR action the moment it returns.

The bridge was written for that: "after an EDR command returns, the
corresponding Splunk event already exists". It is easy to half-build --
a sourcetype named, a shape written, and nothing publishing -- and that is
exactly what had happened to Cortex XDR's endpoints: `pan:xdr:endpoint` was
declared, `shapes.xdr_endpoint` written, sixty such events sat in the seeded
backlog, and no live isolate ever added one. The 200 came back, the SIEM
answered the state the install was seeded with, and a SOAR playbook that
verifies its own action through the SIEM read a stale document.

So this asks the promise of each mount in turn rather than trusting that
whoever added a mutation remembered the bridge. The two that answer nothing
are named with the reason, because a gap nobody has written down is a gap
that comes back.
"""
import json

from fastapi.testclient import TestClient

from repository.splunk.splunk_event_repo import splunk_event_repo

S1_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _events(sourcetype: str) -> int:
    return sum(1 for e in splunk_event_repo.list_all()
               if getattr(e, "sourcetype", "") == sourcetype)


def _oauth(client: TestClient, path: str, form: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {client.post(path, data=form).json()['access_token']}"}


class TestAnActionReachesTheSiem:
    def test_a_sentinelone_agent_action(self, client: TestClient) -> None:
        agent = client.get("/web/api/v2.1/agents", headers=S1_AUTH,
                           params={"limit": 1}).json()["data"][0]["id"]
        before = _events("sentinelone:channel:agents")

        resp = client.post("/web/api/v2.1/agents/actions/disconnect",
                           headers=S1_AUTH, json={"filter": {"ids": [agent]}})

        assert resp.status_code == 200
        assert _events("sentinelone:channel:agents") > before

    def test_a_defender_machine_action(self, client: TestClient) -> None:
        headers = _oauth(client, "/mde/oauth2/v2.0/token", {
            "grant_type": "client_credentials", "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "scope": "https://api.securitycenter.microsoft.com/.default"})
        machine = client.get("/mde/api/machines", headers=headers,
                             params={"$top": 1}).json()["value"][0]["id"]
        before = _events("ms:defender:machines")

        resp = client.post(f"/mde/api/machines/{machine}/isolate", headers=headers,
                           json={"Comment": "bridge", "IsolationType": "Full"})

        assert resp.status_code in (200, 201)
        assert _events("ms:defender:machines") > before

    def test_a_cortex_endpoint_action(self, client: TestClient) -> None:
        headers = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}
        endpoint = client.post("/xdr/public_api/v1/endpoints/get_endpoint", headers=headers,
                               json={"request_data": {}}).json()["reply"]["endpoints"][0]
        before = _events("pan:xdr:endpoint")

        resp = client.post("/xdr/public_api/v1/endpoints/isolate/", headers=headers,
                           json={"request_data": {"endpoint_id": endpoint["endpoint_id"]}})

        assert resp.status_code == 200
        assert _events("pan:xdr:endpoint") == before + 1

    def test_the_cortex_event_carries_the_state_the_action_set(
        self, client: TestClient
    ) -> None:
        headers = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}
        endpoint = client.post("/xdr/public_api/v1/endpoints/get_endpoint", headers=headers,
                               json={"request_data": {}}).json()["reply"]["endpoints"][0]

        client.post("/xdr/public_api/v1/endpoints/isolate/", headers=headers,
                    json={"request_data": {"endpoint_id": endpoint["endpoint_id"]}})

        latest = [e for e in splunk_event_repo.list_all()
                  if getattr(e, "sourcetype", "") == "pan:xdr:endpoint"][-1]
        raw = json.loads(latest.raw) if isinstance(latest.raw, str) else latest.raw
        assert raw["endpoint_id"] == endpoint["endpoint_id"]
        assert raw["is_isolated"] == "isolated", "the SIEM would report it still free"
        assert latest.index == "cortex_xdr"
