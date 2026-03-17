"""Integration tests for Splunk response format validation.

Verifies that all responses conform to the documented Splunk JSON envelope format.
"""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestSplunkEnvelopeFormat:
    """Verify Splunk JSON envelope structure on all endpoint families."""

    def _assert_envelope(self, body: dict) -> None:
        """Assert the response has correct Splunk envelope structure."""
        assert "links" in body, "Missing 'links' in envelope"
        assert "origin" in body, "Missing 'origin' in envelope"
        assert "updated" in body, "Missing 'updated' in envelope"
        assert "generator" in body, "Missing 'generator' in envelope"
        assert "entry" in body, "Missing 'entry' in envelope"
        assert "paging" in body, "Missing 'paging' in envelope"

        # Generator
        gen = body["generator"]
        assert "version" in gen
        assert "build" in gen

        # Paging
        paging = body["paging"]
        assert "total" in paging
        assert "perPage" in paging
        assert "offset" in paging

        # Entry structure
        for entry in body["entry"]:
            assert "name" in entry
            assert "id" in entry
            assert "content" in entry

    def test_server_info_envelope(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/info")
        self._assert_envelope(resp.json())

    def test_indexes_envelope(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/data/indexes", headers=_auth())
        self._assert_envelope(resp.json())

    def test_users_envelope(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/authentication/users", headers=_auth())
        self._assert_envelope(resp.json())

    def test_saved_searches_envelope(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/saved/searches", headers=_auth())
        self._assert_envelope(resp.json())

    def test_roles_envelope(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/authorization/roles", headers=_auth())
        self._assert_envelope(resp.json())

    def test_search_results_envelope(self, client: TestClient) -> None:
        """Search results use a different envelope format."""
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
        body = resp.json()
        assert "results" in body, "Missing 'results' in search envelope"
        assert "fields" in body, "Missing 'fields' in search envelope"
        assert "init_offset" in body, "Missing 'init_offset' in search envelope"
        assert "messages" in body, "Missing 'messages' in search envelope"

    def test_hec_response_format(self, client: TestClient) -> None:
        """HEC uses its own response format."""
        import json
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/event",
            content=json.dumps({"event": {"test": True}}),
            headers={
                "Authorization": "Splunk 11111111-1111-1111-1111-111111111111",
                "Content-Type": "application/json",
            },
        )
        body = resp.json()
        assert "text" in body
        assert "code" in body
        assert body["code"] == 0

    def test_output_mode_param_accepted(self, client: TestClient) -> None:
        """All endpoints should accept output_mode=json parameter."""
        resp = client.get(
            f"{SPLUNK_PREFIX}/services/server/info",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200
