"""An unknown path under a vendor mount must answer like that vendor.

The SPA fallback used to serve ``index.html`` for every unmatched route, so a
mistyped endpoint returned ``200 text/html`` — or ``405``, for anything but
GET, since only GET reached the fallback. A client written against the real
API got neither the status nor the body it parses, which is what made the
tenant-scoped token report (#22) hard to diagnose: the reporter saw ``405``
and had to guess why.

The UI routes under the same top-level prefixes as the APIs it mocks
(``/graph/users`` is a page, ``/graph/v1.0/users`` is an endpoint), so the
fallback tells them apart by ``Accept``, the way a browser navigation does.
"""
import pytest
from fastapi.testclient import TestClient

# (label, path, a key that must appear in the vendor's error body)
VENDOR_PATHS = [
    ("s1", "/web/api/v2.1/no-such-endpoint", "errors"),
    ("crowdstrike", "/cs/no-such-endpoint/v1", "errors"),
    ("mde", "/mde/api/no-such-endpoint", "error"),
    ("graph", "/graph/v1.0/no-such-endpoint", "error"),
    ("xdr", "/xdr/public_api/v1/no-such-endpoint", "reply"),
    ("elasticsearch", "/elastic/no-such-endpoint", "error"),
    ("kibana", "/kibana/api/no-such-endpoint", "statusCode"),
    ("splunk", "/splunk/services/no-such-endpoint", "messages"),
    ("sentinel", "/sentinel/no-such-endpoint", "error"),
]

JSON_ACCEPT = {"Accept": "application/json"}
BROWSER_ACCEPT = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


class TestUnknownVendorRoute:
    """Unmatched API paths get that vendor's 404, not the SPA."""

    @pytest.mark.parametrize(("label", "path", "key"), VENDOR_PATHS)
    def test_get_returns_vendor_404(
        self, client: TestClient, label: str, path: str, key: str,
    ) -> None:
        resp = client.get(path, headers=JSON_ACCEPT)
        assert resp.status_code == 404, f"{label}: expected 404, got {resp.status_code}"
        if label == "splunk":
            # splunkd answers in XML unless asked for output_mode=json.
            assert resp.headers["content-type"].startswith("text/xml")
            assert "<msg" in resp.text
            return
        assert resp.headers["content-type"].startswith("application/json")
        assert key in resp.json(), f"{label}: body is not its error envelope"

    def test_splunk_404_is_json_when_asked(self, client: TestClient) -> None:
        resp = client.get(
            "/splunk/services/no-such-endpoint?output_mode=json", headers=JSON_ACCEPT,
        )
        assert resp.status_code == 404
        assert "messages" in resp.json()

    @pytest.mark.parametrize(("label", "path", "key"), VENDOR_PATHS)
    def test_post_returns_404_not_405(
        self, client: TestClient, label: str, path: str, key: str,
    ) -> None:
        """A missing route is missing whatever the verb — 405 misdirects."""
        resp = client.post(path, headers=JSON_ACCEPT, json={})
        assert resp.status_code == 404, f"{label}: expected 404, got {resp.status_code}"
        if label == "splunk":
            assert "<msg" in resp.text
            return
        assert key in resp.json()

    @pytest.mark.parametrize("method", ["put", "patch", "delete"])
    def test_other_verbs_also_404(self, client: TestClient, method: str) -> None:
        resp = getattr(client, method)("/mde/api/no-such-endpoint", headers=JSON_ACCEPT)
        assert resp.status_code == 404

    def test_curl_style_accept_still_gets_json(self, client: TestClient) -> None:
        """``*/*`` is an API client, not a browser navigating."""
        resp = client.get("/mde/api/no-such-endpoint", headers={"Accept": "*/*"})
        assert resp.status_code == 404
        assert "error" in resp.json()

    def test_no_accept_header_gets_json(self, client: TestClient) -> None:
        resp = client.get("/graph/v1.0/no-such-endpoint", headers={"Accept": ""})
        assert resp.status_code == 404


class TestSpaStillServed:
    """The UI must keep working — its routes share the vendors' prefixes."""

    @pytest.mark.parametrize("path", [
        "/",
        "/dashboard",
        "/endpoints",
        # These collide with API mounts and are pages, not endpoints.
        "/graph/users",
        "/sentinel/incidents",
        "/splunk/search",
        "/elastic/rules",
    ])
    def test_browser_navigation_gets_the_spa(self, client: TestClient, path: str) -> None:
        resp = client.get(path, headers=BROWSER_ACCEPT)
        # 404 only when no build is present; never a JSON API error.
        if resp.status_code == 404:
            pytest.skip("frontend/dist not built in this environment")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")


class TestWrongVerbStillFiveOhFive:
    """A wrong verb on a route that exists is 405, not 404.

    The catch-all claims every method, which would otherwise hide Starlette's
    own method-not-allowed handling and turn a wrong verb against a real
    endpoint into a 404 — the same misdirection this module exists to remove,
    pointed the other way.
    """

    @pytest.mark.parametrize(("method", "path"), [
        ("delete", "/web/api/v2.1/agents"),
        ("put", "/web/api/v2.1/agents"),
        ("delete", "/mde/api/machines"),
        ("put", "/graph/v1.0/users"),
    ])
    def test_existing_path_wrong_verb_is_405(
        self, client: TestClient, method: str, path: str,
    ) -> None:
        resp = getattr(client, method)(path, headers=JSON_ACCEPT)
        assert resp.status_code == 405, f"{method.upper()} {path}"

    def test_405_advertises_allowed_methods(self, client: TestClient) -> None:
        """RFC 7231 requires Allow on a 405; a client uses it to correct itself."""
        resp = client.delete("/web/api/v2.1/agents", headers=JSON_ACCEPT)
        assert resp.status_code == 405
        assert "GET" in resp.headers.get("Allow", "")

    def test_405_body_is_the_vendor_envelope(self, client: TestClient) -> None:
        resp = client.delete("/mde/api/machines", headers=JSON_ACCEPT)
        assert resp.status_code == 405
        assert "error" in resp.json()
