"""Integration tests for threat command endpoints.

POST /threats/analyst-verdict
POST /threats/incident
POST /threats/mitigate/{action}
POST /threats/add-to-blacklist
POST /threats/mark-as-threat
POST /threats/mark-as-resolved
POST /threats/{id}/notes
GET  /threats/{id}/notes
GET  /threats/{id}/fetched-file
POST /threats/fetch-file
POST /threats/dv-add-to-blacklist
POST /threats/dv-mark-as-threat
POST /threats/engines/disable
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _first_threat(client: TestClient, auth_headers: dict) -> dict:
    return client.get(f"{BASE}/threats", headers=auth_headers).json()["data"][0]


class TestAnalystVerdict:
    def test_set_verdict_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/analyst-verdict",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {"verdict": "true_positive"}},
        )
        assert resp.status_code == 200

    def test_set_verdict_returns_affected(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        body = client.post(
            f"{BASE}/threats/analyst-verdict",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {"verdict": "false_positive"}},
        ).json()
        assert "data" in body


class TestIncidentStatus:
    def test_set_incident_status_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/incident",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {"incidentStatus": "resolved"}},
        )
        assert resp.status_code == 200

    def test_set_incident_status_updates_threat(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        client.post(
            f"{BASE}/threats/incident",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {"incidentStatus": "resolved"}},
        )
        threat = client.get(f"{BASE}/threats/{tid}", headers=auth_headers).json()["data"]
        assert threat["threatInfo"]["incidentStatus"] == "resolved"


class TestMitigate:
    def test_quarantine_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/mitigate/quarantine",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}},
        )
        assert resp.status_code == 200

    def test_kill_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/mitigate/kill",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}},
        )
        assert resp.status_code == 200

    def test_remediate_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/mitigate/remediate",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}},
        )
        assert resp.status_code == 200

    def test_rollback_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/mitigate/rollback-remediation",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}},
        )
        assert resp.status_code == 200

    def test_mitigate_updates_status(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        client.post(
            f"{BASE}/threats/mitigate/quarantine",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}},
        )
        threat = client.get(f"{BASE}/threats/{tid}", headers=auth_headers).json()["data"]
        assert threat["threatInfo"]["mitigationStatus"] == "quarantined"


class TestAddToBlacklist:
    def test_add_to_blacklist_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/add-to-blacklist",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200


class TestMarkAsThreat:
    def test_mark_as_threat_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/mark-as-threat",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200


class TestMarkAsResolved:
    def test_mark_as_resolved_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/mark-as-resolved",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200


class TestThreatNotes:
    def test_get_notes_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.get(f"{BASE}/threats/{tid}/notes", headers=auth_headers)
        assert resp.status_code == 200

    def test_get_notes_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(f"{BASE}/threats/nope/notes", headers=auth_headers)
        assert resp.status_code == 404

    def test_add_note_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/{tid}/notes",
            headers=auth_headers,
            json={"text": "Test analyst note"},
        )
        assert resp.status_code == 200

    def test_add_note_unknown_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/threats/nope/notes",
            headers=auth_headers,
            json={"text": "Test note"},
        )
        assert resp.status_code == 404

    def test_note_appears_in_get_notes(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        client.post(
            f"{BASE}/threats/{tid}/notes",
            headers=auth_headers,
            json={"text": "Unique note text 12345"},
        )
        notes = client.get(f"{BASE}/threats/{tid}/notes", headers=auth_headers).json()["data"]
        texts = [n["text"] for n in notes]
        assert any("Unique note text 12345" in t for t in texts)


class TestFetchFile:
    def test_fetch_file_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/fetch-file",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200

    def test_download_fetched_file_after_fetch(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        client.post(
            f"{BASE}/threats/fetch-file",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        resp = client.get(f"{BASE}/threats/{tid}/fetched-file", headers=auth_headers)
        assert resp.status_code == 200

    def test_download_without_fetch_returns_404(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.get(f"{BASE}/threats/{tid}/fetched-file", headers=auth_headers)
        assert resp.status_code == 404


class TestDvThreatActions:
    def test_dv_add_to_blacklist_returns_200(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/dv-add-to-blacklist",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200

    def test_dv_mark_as_threat_returns_200(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/dv-mark-as-threat",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200


class TestBulkThreatNotes:
    def test_bulk_notes_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/notes",
            headers=auth_headers,
            json={"data": {"text": "Bulk note"}, "filter": {"ids": [tid]}},
        )
        assert resp.status_code == 200

    def test_bulk_notes_affected_count(self, client: TestClient, auth_headers: dict) -> None:
        threats = client.get(f"{BASE}/threats", headers=auth_headers).json()["data"]
        ids = [t["id"] for t in threats[:3]]
        resp = client.post(
            f"{BASE}/threats/notes",
            headers=auth_headers,
            json={"data": {"text": "SOC review required"}, "filter": {"ids": ids}},
        )
        assert resp.json()["data"]["affected"] == len(ids)

    def test_bulk_notes_unknown_ids_not_counted(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/threats/notes",
            headers=auth_headers,
            json={"data": {"text": "x"}, "filter": {"ids": ["nope1", "nope2"]}},
        )
        assert resp.json()["data"]["affected"] == 0

    def test_bulk_notes_appear_on_threat(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        client.post(
            f"{BASE}/threats/notes",
            headers=auth_headers,
            json={"data": {"text": "Bulk note unique 99991"}, "filter": {"ids": [tid]}},
        )
        notes = client.get(f"{BASE}/threats/{tid}/notes", headers=auth_headers).json()["data"]
        assert any("Bulk note unique 99991" in n["text"] for n in notes)


class TestDisableEngines:
    def test_disable_engines_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        tid = _first_threat(client, auth_headers)["id"]
        resp = client.post(
            f"{BASE}/threats/engines/disable",
            headers=auth_headers,
            json={"filter": {"ids": [tid]}, "data": {}},
        )
        assert resp.status_code == 200
