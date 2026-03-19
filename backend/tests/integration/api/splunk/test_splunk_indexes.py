"""Integration tests for Splunk index endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestIndexes:
    """Tests for /services/data/indexes endpoints."""

    def test_list_indexes(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/data/indexes", headers=_auth())
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        names = [e["name"] for e in body["entry"]]
        for expected in ["main", "sentinelone", "crowdstrike", "msdefender",
                         "elastic_security", "cortex_xdr", "notable"]:
            assert expected in names, f"Index '{expected}' not found"

    def test_get_index(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/data/indexes/sentinelone",
            headers=_auth(),
        )
        assert resp.status_code == 200
        content = resp.json()["entry"][0]["content"]
        assert "totalEventCount" in content
        # Should have events from seed data
        assert int(content["totalEventCount"]) > 0

    def test_get_nonexistent_index(self, client: TestClient) -> None:
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/data/indexes/nonexistent",
            headers=_auth(),
        )
        assert resp.status_code == 404

    def test_create_index(self, client: TestClient) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/data/indexes",
            json={"name": "test_new_index"},
            headers=_auth(),
        )
        assert resp.status_code == 200

        # Verify it exists
        get_resp = client.get(
            f"{SPLUNK_PREFIX}/services/data/indexes/test_new_index",
            headers=_auth(),
        )
        assert get_resp.status_code == 200

    def test_index_event_counts(self, client: TestClient) -> None:
        """Verify that EDR event seeding populated index counts."""
        resp = client.get(f"{SPLUNK_PREFIX}/services/data/indexes", headers=_auth())
        edr_indexes = {e["name"]: int(e["content"]["totalEventCount"])
                       for e in resp.json()["entry"]
                       if e["name"] in ("sentinelone", "crowdstrike", "msdefender",
                                        "elastic_security", "cortex_xdr")}
        for name, count in edr_indexes.items():
            assert count > 0, f"Index '{name}' has 0 events — seeder may not have run"
