"""A mitigated threat says so in the words the swagger gives it.

``threatInfo.mitigationStatus`` is an enum in the 2.1 swagger —
``not_mitigated``, ``mitigated``, ``marked_as_benign`` — and the mitigate
actions wrote ``killed``, ``quarantined``, ``remediated``, ``rollback`` and
``active`` into it. A client filtering ``mitigationStatuses=mitigated`` never
found the threat it had just mitigated, and one that switches on the enum
fell through every case. The per-action detail has its own documented home:
each threat's top-level ``mitigationStatus`` list, whose entries carry an
``action`` (kill, remediate, rollback, quarantine, unquarantine,
network_quarantine, remove_macros, restore_macros) and a ``status``.

The path enum of ``POST /threats/mitigate/{action}`` also lists
``remove_macros`` and ``restore_macros``, which the mock refused with a 400.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"
S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

#: data/swagger_2_1.json, threats.schemas_ThreatSchema_many_200:
#: data[*].threatInfo.mitigationStatus ...
INFO_ENUM = ["not_mitigated", "mitigated", "marked_as_benign"]
#: ... data[*].mitigationStatus[*].action ...
ACTION_ENUM = ["kill", "remediate", "rollback", "quarantine", "unquarantine",
               "network_quarantine", "remove_macros", "restore_macros"]
#: ... and data[*].mitigationStatus[*].status.
STATUS_ENUM = ["success", "failed", "pending-reboot", "pending", "sent", "partial"]


def _first_threat_id(client: TestClient) -> str:
    return client.get(f"{BASE}/threats", headers=S1, params={"limit": 1}).json()["data"][0]["id"]


def _threat(client: TestClient, tid: str) -> dict:
    return client.get(f"{BASE}/threats", headers=S1, params={"ids": tid}).json()["data"][0]


ACTIONS = [
    ("kill", "mitigated", "kill"),
    ("quarantine", "mitigated", "quarantine"),
    ("remediate", "mitigated", "remediate"),
    ("rollback-remediation", "mitigated", "rollback"),
    ("un-quarantine", "not_mitigated", "unquarantine"),
    ("remove_macros", "mitigated", "remove_macros"),
    ("restore_macros", "not_mitigated", "restore_macros"),
]


class TestMitigationWritesTheEnum:
    """Every documented action leaves values the swagger declares."""

    @pytest.mark.parametrize(("action", "status", "entry_action"), ACTIONS)
    def test_action(
        self, client: TestClient, action: str, status: str, entry_action: str,
    ) -> None:
        tid = _first_threat_id(client)
        resp = client.post(f"{BASE}/threats/mitigate/{action}", headers=S1,
                           json={"filter": {"ids": [tid]}})
        assert resp.status_code == 200, resp.text
        assert resp.json()["data"]["affected"] == 1
        threat = _threat(client, tid)
        assert threat["threatInfo"]["mitigationStatus"] == status
        assert status in INFO_ENUM
        entry = next(e for e in threat["mitigationStatus"] if e["action"] == entry_action)
        assert entry_action in ACTION_ENUM
        assert entry["status"] in STATUS_ENUM

    def test_a_mitigated_threat_is_found_by_its_status(self, client: TestClient) -> None:
        tid = _first_threat_id(client)
        client.post(f"{BASE}/threats/mitigate/kill", headers=S1,
                    json={"filter": {"ids": [tid]}})
        found = client.get(f"{BASE}/threats", headers=S1,
                           params={"mitigationStatuses": "mitigated", "limit": 1000}).json()
        assert tid in {t["id"] for t in found["data"]}

    def test_repeating_an_action_keeps_one_entry_for_it(self, client: TestClient) -> None:
        tid = _first_threat_id(client)
        for _ in range(2):
            client.post(f"{BASE}/threats/mitigate/kill", headers=S1,
                        json={"filter": {"ids": [tid]}})
        actions = [e["action"] for e in _threat(client, tid)["mitigationStatus"]]
        assert actions.count("kill") == 1

    def test_an_action_outside_the_enum_is_refused(self, client: TestClient) -> None:
        resp = client.post(f"{BASE}/threats/mitigate/explode", headers=S1,
                           json={"filter": {"ids": [_first_threat_id(client)]}})
        assert resp.status_code == 400
