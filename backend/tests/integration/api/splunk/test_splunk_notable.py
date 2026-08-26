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


class TestTheTwoEncodingsAgree:
    """The same update, form-encoded and as JSON, has to do the same thing.

    The JSON body was validated against a DTO whose fields were all `str`,
    and any failure was swallowed into an empty parameter set — so a status
    sent as the number it is discarded the whole request and answered
    `success: false, "No event IDs provided"` for a request that named
    three. The form path, on the same route, coerced everything to a string
    and went through.
    """

    def test_a_numeric_status_updates_the_notable(self, client: TestClient) -> None:
        notable_id = _get_notable_ids(client)[0]
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={"ruleUIDs": [notable_id], "status": 2},
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    def test_form_and_json_report_the_same(self, client: TestClient) -> None:
        notable_ids = _get_notable_ids(client)
        as_form = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            data={"ruleUIDs": notable_ids[0], "status": "2", "comment": "form"},
            headers=_auth(),
        ).json()
        as_json = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={"ruleUIDs": [notable_ids[0]], "status": "2", "comment": "json"},
            headers=_auth(),
        ).json()
        assert as_form["success"] == as_json["success"] is True
        assert as_form.get("updated") == as_json.get("updated")

    def test_a_body_that_is_not_an_object_is_still_refused(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json=["not", "an", "object"],
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is False
