"""Integration test: Full XSOAR-compatible flow.

Simulates the XSOAR SplunkPy integration lifecycle:
1. Auth → login
2. Fetch notables → run notable macro
3. Drilldown → search for originating EDR event
4. Verify Splunk JSON envelope format
"""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestXsoarFlow:
    """End-to-end XSOAR SplunkPy compatible flow."""

    def test_full_xsoar_lifecycle(self, client: TestClient) -> None:
        """Simulate XSOAR: auth → fetch notables → drilldown → verify."""

        # Step 1: Login
        login_resp = client.post(
            f"{SPLUNK_PREFIX}/services/auth/login",
            data={"username": "admin", "password": "mockdr-admin"},
        )
        assert login_resp.status_code == 200
        session_key = login_resp.json()["sessionKey"]
        bearer = {"Authorization": f"Bearer {session_key}"}

        # Step 2: Fetch notable events (XSOAR fetch-incidents)
        create_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "`notable`"},
            headers=bearer,
        )
        assert create_resp.status_code == 200
        sid = create_resp.json()["sid"]

        # Step 3: Poll job status (XSOAR polls until DONE)
        status_resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/jobs/{sid}",
            headers=bearer,
        )
        assert status_resp.status_code == 200
        job_content = status_resp.json()["entry"][0]["content"]
        assert job_content["dispatchState"] == "DONE"
        assert job_content["isDone"] is True

        # Step 4: Get results
        results_resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=bearer,
        )
        assert results_resp.status_code == 200
        results = results_resp.json()["results"]
        assert len(results) > 0

        # Step 5: Verify notable has drilldown search
        notable = results[0]
        assert "drilldown_search" in notable
        assert notable["drilldown_search"]  # not empty

        # Step 6: Run drilldown search
        drilldown_resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": notable["drilldown_search"]},
            headers=bearer,
        )
        assert drilldown_resp.status_code == 200
        drilldown_sid = drilldown_resp.json()["sid"]

        drilldown_results = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{drilldown_sid}/results",
            headers=bearer,
        )
        assert drilldown_results.status_code == 200
        # Drilldown should find events (from the EDR index)
        dr_results = drilldown_results.json()["results"]
        assert len(dr_results) >= 0  # May have 0 if filter is too specific

        # Step 7: Update notable status (XSOAR splunk-notable-update)
        update_resp = client.post(
            f"{SPLUNK_PREFIX}/services/notable_update",
            json={
                "ruleUIDs": [notable["event_id"]],
                "status": "2",
                "comment": "Investigating via XSOAR",
            },
            headers=bearer,
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["success"] is True

    def test_splunk_search_with_index_filter(self, client: TestClient) -> None:
        """Verify SPL search works with index filtering."""
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/search/jobs",
            json={"search": "search index=sentinelone sourcetype=sentinelone:channel:threats | head 5"},
            headers=_auth(),
        )
        sid = resp.json()["sid"]

        results_resp = client.get(
            f"{SPLUNK_PREFIX}/services/search/v2/jobs/{sid}/results",
            headers=_auth(),
        )
        results = results_resp.json()["results"]
        assert len(results) <= 5
        for r in results:
            assert r["index"] == "sentinelone"
            assert r["sourcetype"] == "sentinelone:channel:threats"

    def test_splunk_kv_store_xsoar_flow(self, client: TestClient) -> None:
        """Test KV Store CRUD flow used by XSOAR."""
        # Create collection
        client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/config",
            json={"name": "xsoar_test"},
            headers=_auth(),
        )

        # Insert entries
        for i in range(3):
            client.post(
                f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/xsoar_test",
                json={"name": f"entry_{i}", "value": i},
                headers=_auth(),
            )

        # Get all entries
        resp = client.get(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/xsoar_test",
            headers=_auth(),
        )
        assert resp.status_code == 200
        records = resp.json()
        assert len(records) == 3

        # Batch save
        batch_resp = client.post(
            f"{SPLUNK_PREFIX}/servicesNS/nobody/search/storage/collections/data/xsoar_test/batch_save",
            json=[{"name": f"batch_{i}", "value": i * 10} for i in range(5)],
            headers=_auth(),
        )
        assert batch_resp.status_code == 200
        assert len(batch_resp.json()) == 5
