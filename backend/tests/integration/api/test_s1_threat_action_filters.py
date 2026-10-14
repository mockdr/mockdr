"""A threat action selects what its whole filter says, and only documented values.

The swagger's request schemas for the threat actions
(``threats.schemas_ThreatsMitigateRequestSchema``,
``ThreatsAnalystVerdictSchema``, ``ThreatsIncidentSchema``,
``ThreatsAddToRestrictionsWithTargetSchema``, ``ThreatsNoteCreateSchema``,
``ThreatsFetchFileRequestSchema``) declare the same filter members as
``GET /threats`` — ``agentIds``, ``siteIds``, ``resolved``,
``contentHashes``, … The actions read ``filter.ids`` and nothing else: a
mitigation scoped to one agent's threats matched nothing and answered
``{"affected": 0}`` with a 200, and the client believed it.

* The filter goes through the list route's engine, so an action selects what
  a GET with the same parameters lists; a member the mock cannot select on
  is refused rather than ignored (ignoring it widens the selection).
* An empty filter is every threat where the swagger says so — "You can also
  leave this field empty to apply to all available threats" on mitigate,
  add-to-blacklist and fetch-file — and nothing elsewhere, as before.
* fetch-file: "Filter must match exactly one threat. Bulk operations are not
  supported."
* ``data.analystVerdict`` (undefined | true_positive | false_positive |
  suspicious) and ``data.incidentStatus`` (unresolved | in_progress |
  resolved) are enums; any string was stored. The incident schema's optional
  ``data.analystVerdict`` was dropped; it is applied.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}


def _threats(client: TestClient, **params: object) -> list[dict]:
    return client.get(f"{BASE}/threats", headers=S1,
                      params={"limit": 1000, **params}).json()["data"]


def _an_agent_with_threats(client: TestClient) -> tuple[str, set[str]]:
    by_agent: dict[str, set[str]] = {}
    for t in _threats(client):
        by_agent.setdefault(t["agentRealtimeInfo"]["agentId"], set()).add(t["id"])
    agent_id = max(by_agent, key=lambda a: len(by_agent[a]))
    return agent_id, by_agent[agent_id]


class TestTheWholeFilterSelects:
    """Members other than ``ids`` narrow the action, as they narrow the list."""

    def test_mitigate_by_agent_ids(self, client: TestClient) -> None:
        agent_id, expected = _an_agent_with_threats(client)
        resp = client.post(f"{BASE}/threats/mitigate/kill", headers=S1,
                           json={"filter": {"agentIds": [agent_id]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == len(expected)
        killed = {t["id"] for t in _threats(client) if any(
            e.get("action") == "kill" for e in t["mitigationStatus"])}
        assert killed == expected

    def test_analyst_verdict_by_content_hash(self, client: TestClient) -> None:
        target = _threats(client)[0]
        sha1 = target["threatInfo"]["sha1"]
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=S1, json={
            "filter": {"contentHashes": [sha1]},
            "data": {"analystVerdict": "false_positive"},
        })
        assert resp.json()["data"]["affected"] >= 1
        assert _threats(client, ids=target["id"])[0]["threatInfo"]["analystVerdict"] \
            == "false_positive"

    def test_incident_by_resolved_false_matches_the_list(self, client: TestClient) -> None:
        unresolved = {t["id"] for t in _threats(client, resolved="false")}
        resp = client.post(f"{BASE}/threats/incident", headers=S1, json={
            "filter": {"resolved": False},
            "data": {"incidentStatus": "in_progress"},
        })
        assert resp.json()["data"]["affected"] == len(unresolved)

    def test_a_member_the_mock_cannot_select_on_is_refused(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/threats/mitigate/kill", headers=S1,
                           json={"filter": {"noSuchMember": ["x"]}})
        assert resp.status_code == 400
        assert "noSuchMember" in resp.json()["errors"][0]["detail"]
        assert all(not t["mitigationStatus"] for t in _threats(client))

    def test_ids_still_select(self, client: TestClient) -> None:
        tid = _threats(client)[0]["id"]
        resp = client.post(f"{BASE}/threats/mitigate/quarantine", headers=S1,
                           json={"filter": {"ids": [tid]}})
        assert resp.json()["data"]["affected"] == 1


class TestAnEmptyFilter:
    """Every threat where the swagger says so, nothing where it does not."""

    def test_mitigate_applies_to_every_threat(self, client: TestClient) -> None:
        total = len(_threats(client))
        resp = client.post(f"{BASE}/threats/mitigate/kill", headers=S1, json={"filter": {}})
        assert resp.json()["data"]["affected"] == total

    def test_analyst_verdict_applies_to_none(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/threats/analyst-verdict", headers=S1, json={
            "filter": {}, "data": {"analystVerdict": "suspicious"}})
        assert resp.json()["data"]["affected"] == 0


class TestFetchFileTakesOneThreat:
    """"Filter must match exactly one threat."""

    def test_one_threat_is_fetched(self, client: TestClient) -> None:
        tid = _threats(client)[0]["id"]
        resp = client.post(f"{BASE}/threats/fetch-file", headers=S1, json={
            "filter": {"ids": [tid]}, "data": {"password": "Infected123!"}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_several_are_refused(self, client: TestClient) -> None:
        ids = [t["id"] for t in _threats(client)[:2]]
        resp = client.post(f"{BASE}/threats/fetch-file", headers=S1, json={
            "filter": {"ids": ids}, "data": {"password": "Infected123!"}})
        assert resp.status_code == 400


class TestDocumentedValues:
    """Verdicts and statuses outside the swagger's enums are refused."""

    @pytest.mark.parametrize(("path", "data"), [
        ("/threats/analyst-verdict", {"analystVerdict": "bogus"}),
        ("/threats/incident", {"incidentStatus": "closed"}),
        ("/threats/incident", {"incidentStatus": "resolved", "analystVerdict": "bogus"}),
    ])
    def test_refused(self, client: TestClient, path: str, data: dict) -> None:
        target = _threats(client)[0]
        resp = client.post(f"{BASE}{path}", headers=S1,
                           json={"filter": {"ids": [target["id"]]}, "data": data})
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == 4000010
        after = _threats(client, ids=target["id"])[0]["threatInfo"]
        assert after["analystVerdict"] == target["threatInfo"]["analystVerdict"]
        assert after["incidentStatus"] == target["threatInfo"]["incidentStatus"]

    def test_incident_sets_the_verdict_it_carries(self, client: TestClient) -> None:
        tid = _threats(client)[0]["id"]
        client.post(f"{BASE}/threats/incident", headers=S1, json={
            "filter": {"ids": [tid]},
            "data": {"incidentStatus": "resolved", "analystVerdict": "true_positive"}})
        info = _threats(client, ids=tid)[0]["threatInfo"]
        assert info["incidentStatus"] == "resolved"
        assert info["analystVerdict"] == "true_positive"
