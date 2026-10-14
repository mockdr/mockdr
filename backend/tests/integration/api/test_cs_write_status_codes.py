"""A Falcon write answers with the success code gofalcon is generated to expect.

go-swagger generates one ``case`` per documented status in each reader, and
any other code falls to ``default`` and comes back as an error. Three routes
answered 200 where Falcon documents something else, so gofalcon reported a
successful write as a failure:

* ``POST /devices/entities/devices-actions/v2`` — 202 only
  (``perform_action_v2_responses.go``: ``PerformActionV2Accepted``; no 200
  among its answers). The action is queued for the sensor, which is why a
  contained host shows ``containment_pending`` first.
* ``POST /iocs/entities/indicators/v1`` — 201
  (``indicator_create_v1_responses.go``: ``IndicatorCreateV1Created``).
* ``POST /devices/entities/host-groups/v1`` — 201
  (``create_host_groups_responses.go``: ``CreateHostGroupsCreated``).

Every other write route on the mount is documented with 200 (the PATCH of
device tags with 200 or 202), which is what it answers.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestDocumentedSuccessCodes:
    """Each write answers the one success code its reader has a case for."""

    def test_device_action_is_accepted(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        device_id = client.get("/cs/devices/queries/devices/v1", headers=headers,
                               params={"limit": 1}).json()["resources"][0]
        resp = client.post("/cs/devices/entities/devices-actions/v2", headers=headers,
                           params={"action_name": "contain"}, json={"ids": [device_id]})
        assert resp.status_code == 202
        assert resp.json()["resources"][0]["id"] == device_id

    def test_ioc_create_is_created(self, client: TestClient) -> None:
        resp = client.post("/cs/iocs/entities/indicators/v1", headers=_cs_auth(client),
                           json={"indicators": [{
                               "type": "domain", "value": "status-code.example",
                               "action": "detect", "severity": "low",
                               "platforms": ["windows"],
                           }]})
        assert resp.status_code == 201
        assert resp.json()["resources"][0]["value"] == "status-code.example"

    def test_host_group_create_is_created(self, client: TestClient) -> None:
        resp = client.post("/cs/devices/entities/host-groups/v1", headers=_cs_auth(client),
                           json={"resources": [{"name": "status-codes",
                                                "group_type": "static"}]})
        assert resp.status_code == 201
        assert resp.json()["resources"][0]["name"] == "status-codes"
