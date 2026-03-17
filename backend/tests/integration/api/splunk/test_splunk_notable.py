"""Integration tests for Splunk notable event endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


def _get_notable_ids(client: TestClient) -> list[str]:
    """Get notable event IDs via the notable macro."""
    create_resp = client.post(
        f"{SPLUNK_PREFIX}/services/search/jobs",
        json={"search": "`notable`"},
        headers=_auth(),
    )
    sid = create_resp.json()["sid"]
    results_resp = client.get(
        f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
        headers=_auth(),
    )
    results = results_resp.json()["results"]
    return [r["event_id"] for r in results[:3]]


class TestNotableUpdate:
    """Tests for POST /services/notable_update."""

    def test_update_notable_status(self, client: TestClient) -> None:
        notable_ids = _get_notable_ids(client)
        assert len(notable_ids) > 0

        resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={
                "ruleUIDs": [notable_ids[0]],
                "status": "2",
            },
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_update_notable_urgency(self, client: TestClient) -> None:
        notable_ids = _get_notable_ids(client)
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={
                "ruleUIDs": [notable_ids[0]],
                "newUrgency": "critical",
            },
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_update_notable_owner(self, client: TestClient) -> None:
        notable_ids = _get_notable_ids(client)
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={
                "ruleUIDs": [notable_ids[0]],
                "newOwner": "analyst",
            },
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_update_notable_with_comment(self, client: TestClient) -> None:
        notable_ids = _get_notable_ids(client)
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={
                "ruleUIDs": [notable_ids[0]],
                "comment": "Investigating this alert",
                "status": "2",
            },
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_update_multiple_notables(self, client: TestClient) -> None:
        notable_ids = _get_notable_ids(client)
        if len(notable_ids) >= 2:
            resp = client.post(
                f"{SPLUNK_PREFIX}/services/notable_update",
                json={
                    "ruleUIDs": notable_ids[:2],
                    "status": "4",
                },
                headers=_auth(),
            )
            assert resp.status_code == 200
            assert "Updated 2" in resp.json()["message"]

    def test_notable_fields_complete(self, client: TestClient) -> None:
        """Verify notable events have all fields XSOAR expects."""
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "`notable`"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]
        results_resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=_auth(),
        )
        results = results_resp.json()["results"]
        assert len(results) > 0

        required_fields = [
            "event_id", "rule_name", "security_domain", "severity",
            "urgency", "status", "status_label", "owner",
            "description", "drilldown_search", "time", "_time",
        ]
        notable = results[0]
        for field in required_fields:
            assert field in notable, f"Notable missing required field '{field}'"
