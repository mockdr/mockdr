"""Three verbs Falcon documents and this mock answered 405 to.

`scripts/method_drift.py` compares every documented operation against what
the mock serves — and its CrowdStrike entry named the prefix `/crowdstrike`
where the mount is `/cs`. So the comparison matched no route at all and
passed over the whole CrowdStrike surface in silence: 208 operations
checked, where the corrected prefix checks 247. The three it had been
hiding:

    GET   /devices/entities/devices/v2          the ids-in-query read, which
                                                gofalcon's own client uses
    PATCH /alerts/entities/alerts/v2            the update under the version
                                                that names the ids `ids`
    PATCH /quarantine/queries/quarantined-files/v1
                                                the by-filter twin of an
                                                action already served by ids

A 200 is not the point here — each test checks the call did what it says.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

CS = "/cs"


@pytest.fixture
def cs_headers(client: TestClient) -> dict[str, str]:
    resp = client.post(f"{CS}/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret"})
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestTheDeviceReadUnderBothVerbs:
    def test_they_answer_the_same_entities(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        ids = client.get(f"{CS}/devices/queries/devices/v1", headers=cs_headers,
                         params={"limit": 3}).json()["resources"]
        assert len(ids) == 3

        by_query = client.get(f"{CS}/devices/entities/devices/v2",
                              headers=cs_headers, params={"ids": ",".join(ids)})
        by_body = client.post(f"{CS}/devices/entities/devices/v2",
                              headers=cs_headers, json={"ids": ids})
        assert by_query.status_code == 200, by_query.text
        assert by_body.status_code == 200, by_body.text
        assert by_query.json()["resources"] == by_body.json()["resources"]
        assert len(by_query.json()["resources"]) == 3


class TestTheAlertUpdateUnderBothVersions:
    @staticmethod
    def _status(client: TestClient, headers: dict, cid: str) -> str:
        resp = client.post(f"{CS}/alerts/entities/alerts/v2", headers=headers,
                           json={"composite_ids": [cid]})
        return str((resp.json()["resources"][0] or {}).get("status"))

    def test_v2_names_the_ids_ids_and_still_changes_the_alert(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        cid = client.get(f"{CS}/alerts/queries/alerts/v2", headers=cs_headers,
                         params={"limit": 1}).json()["resources"][0]
        before = self._status(client, cs_headers, cid)

        resp = client.patch(f"{CS}/alerts/entities/alerts/v2", headers=cs_headers, json={
            "ids": [cid],
            "action_parameters": [{"name": "update_status", "value": "in_progress"}]})
        assert resp.status_code == 200, resp.text
        # DetectsapiResponseFields: meta and errors, no resources.
        assert "resources" not in resp.json()
        assert self._status(client, cs_headers, cid) == "in_progress" != before

    def test_v3_still_takes_composite_ids(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        cid = client.get(f"{CS}/alerts/queries/alerts/v2", headers=cs_headers,
                         params={"limit": 1}).json()["resources"][0]
        resp = client.patch(f"{CS}/alerts/entities/alerts/v3", headers=cs_headers, json={
            "composite_ids": [cid],
            "action_parameters": [{"name": "update_status", "value": "closed"}]})
        assert resp.status_code == 200, resp.text
        assert self._status(client, cs_headers, cid) == "closed"


class TestTheQuarantineActionByFilter:
    @staticmethod
    def _states(client: TestClient, headers: dict) -> set[str]:
        ids = client.get(f"{CS}/quarantine/queries/quarantined-files/v1",
                         headers=headers, params={"limit": 100}).json()["resources"]
        resp = client.post(f"{CS}/quarantine/entities/quarantined-files/GET/v1",
                           headers=headers, json={"ids": ids})
        return {str(r.get("state")) for r in resp.json().get("resources") or []}

    def test_it_reaches_every_file_the_filter_selects(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        before = self._states(client, cs_headers)
        assert len(before) > 1, "all files already in one state; nothing to move"

        resp = client.patch(f"{CS}/quarantine/queries/quarantined-files/v1",
                            headers=cs_headers, json={"filter": "", "action": "delete"})
        assert resp.status_code == 200, resp.text
        # MsaReplyMetaOnly: meta and errors, no resources.
        assert "resources" not in resp.json()
        assert self._states(client, cs_headers) == {"deleted"}
