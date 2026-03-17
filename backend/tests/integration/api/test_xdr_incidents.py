"""Integration tests for Cortex XDR Incidents endpoints.

Verifies incident listing, filtering, pagination, extra data retrieval,
and update operations against the mock XDR API.
"""
import hashlib
import hmac
import secrets
import time

from fastapi.testclient import TestClient

XDR_PREFIX = "/xdr/public_api/v1"


def _xdr_headers(
    key_id: str = "1",
    key_secret: str = "xdr-admin-secret",
) -> dict[str, str]:
    """Build valid XDR HMAC auth headers."""
    nonce = secrets.token_hex(32)
    timestamp = str(int(time.time() * 1000))
    # HMAC-SHA256: key_secret as HMAC key, nonce:timestamp as message
    auth_hash = hmac.new(key_secret.encode(), (nonce + ":" + timestamp).encode(), hashlib.sha256).hexdigest()
    return {
        "x-xdr-auth-id": key_id,
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": timestamp,
        "Authorization": auth_hash,
    }


class TestGetIncidents:
    """Tests for POST /incidents/get_incidents/."""

    def test_get_incidents_returns_200(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_response_has_reply_envelope(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        body = resp.json()
        assert "reply" in body
        reply = body["reply"]
        assert "total_count" in reply
        assert "result_count" in reply
        assert "incidents" in reply

    def test_incidents_have_expected_fields(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        incidents = resp.json()["reply"]["incidents"]
        assert len(incidents) > 0
        incident = incidents[0]
        required_fields = [
            "incident_id", "description", "severity", "status",
            "alert_count", "creation_time", "modification_time",
            "hosts", "users", "incident_sources",
        ]
        for field in required_fields:
            assert field in incident, f"Required field '{field}' missing from incident"

    def test_total_count_matches_data(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        assert reply["total_count"] >= reply["result_count"]
        assert reply["result_count"] == len(reply["incidents"])

    def test_filter_by_severity(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {
                "filters": [{"field": "severity", "value": ["high"]}],
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        incidents = resp.json()["reply"]["incidents"]
        for inc in incidents:
            assert inc["severity"] == "high"

    def test_filter_by_status(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {
                "filters": [{"field": "status", "value": ["new"]}],
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        incidents = resp.json()["reply"]["incidents"]
        for inc in incidents:
            assert inc["status"] == "new"

    def test_pagination_search_from_search_to(self, client: TestClient) -> None:
        """Pagination via search_from/search_to produces disjoint pages."""
        headers = _xdr_headers()
        r1 = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {"search_from": 0, "search_to": 2}},
            headers=headers,
        )
        r2 = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {"search_from": 2, "search_to": 4}},
            headers=headers,
        )
        ids1 = {i["incident_id"] for i in r1.json()["reply"]["incidents"]}
        ids2 = {i["incident_id"] for i in r2.json()["reply"]["incidents"]}
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"

    def test_empty_filter_returns_all(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {"filters": []}},
            headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        assert reply["total_count"] > 0


class TestGetIncidentExtraData:
    """Tests for POST /incidents/get_incident_extra_data/."""

    def _get_first_incident_id(self, client: TestClient) -> str:
        """Return the first incident ID from the listing."""
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        return resp.json()["reply"]["incidents"][0]["incident_id"]

    def test_extra_data_returns_200(self, client: TestClient) -> None:
        incident_id = self._get_first_incident_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incident_extra_data/",
            json={"request_data": {"incident_id": incident_id}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

    def test_extra_data_contains_incident_and_alerts(self, client: TestClient) -> None:
        incident_id = self._get_first_incident_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incident_extra_data/",
            json={"request_data": {"incident_id": incident_id}},
            headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        assert "incident" in reply
        assert "alerts" in reply
        assert "network_artifacts" in reply
        assert "file_artifacts" in reply
        assert reply["incident"]["incident_id"] == incident_id

    def test_nonexistent_incident_returns_500(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incident_extra_data/",
            json={"request_data": {"incident_id": "nonexistent-id"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 500


class TestUpdateIncident:
    """Tests for POST /incidents/update_incident/."""

    def _get_first_incident_id(self, client: TestClient) -> str:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incidents/",
            json={"request_data": {}},
            headers=_xdr_headers(),
        )
        return resp.json()["reply"]["incidents"][0]["incident_id"]

    def test_update_status(self, client: TestClient) -> None:
        incident_id = self._get_first_incident_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/update_incident/",
            json={"request_data": {
                "incident_id": incident_id,
                "update_data": {"status": "under_investigation"},
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        assert resp.json()["reply"] is True

    def test_update_assignee(self, client: TestClient) -> None:
        incident_id = self._get_first_incident_id(client)
        resp = client.post(
            f"{XDR_PREFIX}/incidents/update_incident/",
            json={"request_data": {
                "incident_id": incident_id,
                "update_data": {
                    "assigned_user_mail": "analyst@acmecorp.internal",
                    "assigned_user_pretty_name": "Jane Analyst",
                },
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200

        # Verify assignment persisted
        extra_resp = client.post(
            f"{XDR_PREFIX}/incidents/get_incident_extra_data/",
            json={"request_data": {"incident_id": incident_id}},
            headers=_xdr_headers(),
        )
        incident = extra_resp.json()["reply"]["incident"]
        assert incident["assigned_user_mail"] == "analyst@acmecorp.internal"

    def test_update_nonexistent_incident_returns_500(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/incidents/update_incident/",
            json={"request_data": {
                "incident_id": "nonexistent-id",
                "update_data": {"status": "resolved_true_positive"},
            }},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 500
