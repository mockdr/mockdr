"""Integration tests for Splunk server info endpoints."""
import base64

from fastapi.testclient import TestClient

SPLUNK_PREFIX = "/splunk"


def _auth() -> dict[str, str]:
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}


class TestServerInfo:
    """Tests for /services/server/* endpoints."""

    def test_server_info_requires_auth(self, client: TestClient) -> None:
        """This asserted the opposite — open 'for health checks'. splunkd
        answers an anonymous caller 401 (measured on 10.4.2); its
        unauthenticated health endpoint is HEC's /services/collector/health.
        """
        assert client.get(f"{SPLUNK_PREFIX}/services/server/info").status_code == 401

    def test_server_info_content(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/info", headers=_auth())
        assert resp.status_code == 200
        body = resp.json()
        assert "entry" in body
        content = body["entry"][0]["content"]
        assert content["version"] == "9.4.0"
        assert content["product_type"] == "enterprise"

    def test_server_status(self, client: TestClient) -> None:
        """``server/status`` is a collection of seven sub-resources on splunkd.

        Each entry's content is only ``eai:acl``; ``limits`` and
        ``resource-usage`` can be reloaded; there is no top-level link and no
        fields block. Measured on 10.4.2 — it used to be an invented
        ``{"health": "green"}`` document.
        """
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/status", headers=_auth())
        assert resp.status_code == 200
        body = resp.json()
        names = [e["name"] for e in body["entry"]]
        assert names == [
            "conf-resource-usage", "dispatch-artifacts", "fishbucket",
            "installed-file-integrity", "limits", "partitions-space", "resource-usage",
        ]
        assert body["links"] == {}
        by_name = {e["name"]: e for e in body["entry"]}
        assert by_name["fishbucket"]["content"] == {"eai:acl": None}
        assert "fields" not in by_name["fishbucket"]
        assert sorted(by_name["fishbucket"]["links"]) == ["alternate", "list"]
        assert sorted(by_name["limits"]["links"]) == ["_reload", "alternate", "list"]

    def test_server_settings(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/settings", headers=_auth())
        assert resp.status_code == 200

    def test_response_envelope_format(self, client: TestClient) -> None:
        """Verify Splunk JSON envelope structure."""
        resp = client.get(f"{SPLUNK_PREFIX}/services/server/info", headers=_auth())
        body = resp.json()
        assert "links" in body
        assert "origin" in body
        assert "updated" in body
        assert "generator" in body
        assert "entry" in body
        assert "paging" in body
        assert "version" in body["generator"]
        assert "build" in body["generator"]
        assert "total" in body["paging"]
        assert "perPage" in body["paging"]
        assert "offset" in body["paging"]
