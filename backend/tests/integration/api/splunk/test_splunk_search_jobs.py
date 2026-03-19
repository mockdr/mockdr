"""Integration tests for Splunk search job endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestCreateSearchJob:
    """Tests for POST /services/search/jobs."""

    def test_create_job_returns_sid(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert "sid" in resp.json()

    def test_create_job_without_search_fails(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={},
            headers=_auth(),
        )
        assert resp.status_code == 400

    def test_create_job_form_encoded(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            data={"search": "search index=crowdstrike", "output_mode": "json"},
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert "sid" in resp.json()


class TestGetSearchJob:
    """Tests for GET /services/search/jobs/{sid}."""

    def test_get_job_status(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}",
            headers=_auth(),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        content = body["entry"][0]["content"]
        assert content["dispatchState"] == "DONE"
        assert content["isDone"] is True

    def test_nonexistent_job_returns_404(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs/nonexistent",
            headers=_auth(),
        )
        assert resp.status_code == 404


class TestGetResults:
    """Tests for GET /services/search/v2/jobs/{sid}/results."""

    def test_get_results(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=_auth(),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert "fields" in body
        assert isinstance(body["results"], list)

    def test_results_with_pagination(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            params={"count": 5, "offset": 0},
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert len(resp.json()["results"]) <= 5

    def test_notable_macro_search(self, client: TestClient) -> None:
        """XSOAR fetches incidents by running the notable macro."""
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "`notable`"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=_auth(),
        )
        assert resp.status_code == 200
        results = resp.json()["results"]
        assert len(results) > 0
        # Verify notable event fields
        notable = results[0]
        for field in ["event_id", "rule_name", "severity", "status", "owner"]:
            assert field in notable, f"Notable missing field '{field}'"


class TestSearchJobLifecycle:
    """Tests for job control and deletion."""

    def test_list_jobs(self, client: TestClient) -> None:
        client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=main"},
            headers=_auth(),
        )
        resp = client.get(f"{SPLUNK_PREFIX}/services/search/jobs", headers=_auth())
        assert resp.status_code == 200
        assert "entry" in resp.json()

    def test_cancel_job(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=main"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/control",
            json={"action": "cancel"},
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_delete_job(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=main"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.delete(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}",
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_export_search(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs/export",
            params={"search": "search index=sentinelone | head 5"},
            headers=_auth(),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "results" in body
        assert len(body["results"]) <= 5

    def test_get_job_summary(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/summary",
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert "fields" in resp.json()

    def test_get_job_timeline(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}/timeline",
            headers=_auth(),
        )
        assert resp.status_code == 200

    def test_get_job_events(self, client: TestClient) -> None:
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone"},
            headers=_auth(),
        )
        sid = create_resp.json()["sid"]

        resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/events",
            headers=_auth(),
        )
        assert resp.status_code == 200
        assert "results" in resp.json()
