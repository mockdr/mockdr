"""Error paths that bypass the normal handler chain, or that no vendor uses.

Each case here was reachable in a way that handed the caller a body no real
client could parse: a bare ``500`` in ``text/plain``, another vendor's
envelope, or a status none of the mocked APIs emit.
"""
import base64

import pytest
from fastapi.testclient import TestClient

S1_AUTH = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}


def _mde_token(client: TestClient) -> str:
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    })
    return str(resp.json()["access_token"])


def _graph_token(client: TestClient) -> str:
    resp = client.post("/graph/oauth2/v2.0/token", data={
        "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    })
    return str(resp.json()["access_token"])


class TestMalformedJsonBody:
    """Handlers reading the body directly let the decode error escape as a 500."""

    def test_graph_malformed_body_is_vendor_400(self, client: TestClient) -> None:
        token = _graph_token(client)
        users = client.get("/graph/v1.0/users", headers={"Authorization": f"Bearer {token}"})
        user_id = users.json()["value"][0]["id"]

        resp = client.post(
            f"/graph/v1.0/users/{user_id}/sendMail",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            content='{"broken":',
        )
        assert resp.status_code == 400
        assert resp.headers["content-type"].startswith("application/json")
        assert "error" in resp.json()

    def test_s1_malformed_body_is_vendor_400(self, client: TestClient) -> None:
        resp = client.post(
            "/web/api/v2.1/_dev/webhook-sink",
            headers={**S1_AUTH, "Content-Type": "application/json"},
            content="{not json",
        )
        assert resp.status_code == 400
        assert "errors" in resp.json()

    def test_no_response_is_ever_plain_text_500(self, client: TestClient) -> None:
        """The old failure mode: `500 Internal Server Error` as text/plain."""
        resp = client.post(
            "/web/api/v2.1/_dev/webhook-sink",
            headers={**S1_AUTH, "Content-Type": "application/json"},
            content="{",
        )
        assert resp.status_code != 500
        assert not resp.headers["content-type"].startswith("text/plain")


class TestNoFastApiShapesLeak:
    """422 and a top-level ``detail`` belong to FastAPI, not to any vendor."""

    @pytest.mark.parametrize("path", [
        "/web/api/v2.1/dv/events",
        "/web/api/v2.1/dv/query-status",
        "/web/api/v2.1/dv/events/process",
    ])
    def test_missing_query_param_is_400_not_422(
        self, client: TestClient, path: str,
    ) -> None:
        resp = client.get(path, headers=S1_AUTH)
        assert resp.status_code == 400
        assert "errors" in resp.json()
        assert "detail" not in resp.json()

    def test_negative_page_size_is_rejected(self, client: TestClient) -> None:
        """A negative page size is nonsense; only the upper bound was checked."""
        token = _mde_token(client)
        resp = client.get(
            "/mde/api/machines",
            headers={"Authorization": f"Bearer {token}"},
            params={"$top": -5},
        )
        assert resp.status_code == 400
        assert "error" in resp.json()


class TestThrottlingEnvelope:
    """Rate limiting writes raw ASGI, so it never reached the error handler."""

    def test_429_uses_the_target_vendors_envelope(self, client: TestClient) -> None:
        client.post(
            "/web/api/v2.1/_dev/rate-limit",
            headers=S1_AUTH,
            json={"enabled": True, "requestsPerMinute": 1},
        )
        try:
            token = _mde_token(client)
            headers = {"Authorization": f"Bearer {token}"}
            client.get("/mde/api/machines", headers=headers)
            resp = client.get("/mde/api/machines", headers=headers)

            assert resp.status_code == 429
            body = resp.json()
            assert "error" in body, "MDE was handed SentinelOne's envelope"
            assert body["error"]["code"] == "TooManyRequests"
            assert resp.headers.get("Retry-After"), "a throttled client needs a wait hint"
        finally:
            client.post(
                "/web/api/v2.1/_dev/rate-limit",
                headers=S1_AUTH,
                json={"enabled": False, "requestsPerMinute": 60},
            )


class TestHeadIsServed:
    """RFC 9110 makes HEAD mandatory wherever GET is served."""

    @pytest.mark.parametrize("path", [
        "/web/api/v2.1/agents",
        "/mde/api/machines",
    ])
    def test_head_matches_get_without_a_body(self, client: TestClient, path: str) -> None:
        token = _mde_token(client)
        headers = {**S1_AUTH, "Authorization": f"Bearer {token}"} if "mde" in path else S1_AUTH
        get = client.get(path, headers=headers)
        head = client.head(path, headers=headers)
        assert head.status_code == get.status_code
        assert head.content == b""

    def test_head_on_unknown_path_still_404s(self, client: TestClient) -> None:
        assert client.head("/mde/api/no-such-endpoint").status_code == 404


class TestSplunkHecEnvelope:
    """HEC is a different service from splunkd and does not share its shape."""

    def test_hec_unknown_path_uses_the_hec_envelope(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/collector/nope", json={})
        assert resp.status_code == 404
        body = resp.json()
        assert set(body) == {"text", "code"}, "splunkd's `messages` envelope is not HEC's"

    def test_splunkd_path_keeps_the_messages_envelope(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/nope?output_mode=json")
        assert resp.status_code == 404
        assert "messages" in resp.json()


class TestTokenEndpointsSpeakOAuth:
    """A token endpoint fronts Entra, not the API it sits in front of."""

    @pytest.mark.parametrize("path", [
        "/mde/oauth2/v2.0/token",
        "/graph/oauth2/v2.0/token",
        "/sentinel/oauth2/v2.0/token",
    ])
    def test_missing_fields_use_the_oauth_envelope(
        self, client: TestClient, path: str,
    ) -> None:
        resp = client.post(path, data={})
        assert resp.status_code == 400
        body = resp.json()
        assert body["error"] == "invalid_request", "MSAL reads a flat `error` string"
        assert "error_description" in body
        assert not isinstance(body["error"], dict), "not the resource-plane envelope"


class TestElasticIndexResolution:
    """The four index-addressed endpoints must agree with each other."""

    @pytest.mark.parametrize("suffix", ["_search", "_mapping", "_stats"])
    def test_ignore_unavailable_honoured_everywhere(
        self, client: TestClient, suffix: str,
    ) -> None:
        method = client.post if suffix == "_search" else client.get
        resp = method(
            f"/elastic/nosuchindex/{suffix}?ignore_unavailable=true", headers=ES_AUTH,
        )
        assert resp.status_code == 200, f"{suffix} ignored the parameter"

    def test_leading_wildcard_does_not_match_everything(self, client: TestClient) -> None:
        """``*zzz`` selected the whole cluster when the literal part was empty."""
        resp = client.post("/elastic/*zzz/_search", headers=ES_AUTH, json={})
        assert resp.status_code == 200
        assert resp.json()["hits"]["total"]["value"] == 0

    def test_wildcard_mapping_matches_wildcard_search(self, client: TestClient) -> None:
        """A pattern that finds documents must also describe their fields."""
        hits = client.post("/elastic/logs-*/_search", headers=ES_AUTH, json={})
        mapping = client.get("/elastic/logs-*/_mapping", headers=ES_AUTH)
        assert hits.json()["hits"]["total"]["value"] > 0
        props = mapping.json()["logs-*"]["mappings"]["properties"]
        assert props, "search resolved the wildcard but mapping reported no fields"

    def test_uppercase_index_cannot_exist(self, client: TestClient) -> None:
        """Elasticsearch forbids uppercase index names outright."""
        resp = client.post("/elastic/LOGS-ENDPOINT/_search", headers=ES_AUTH, json={})
        assert resp.status_code == 404

    def test_doc_rejects_a_multi_index_expression(self, client: TestClient) -> None:
        resp = client.get("/elastic/_all/_doc/anything", headers=ES_AUTH)
        assert resp.status_code == 400
        assert resp.json()["error"]["type"] == "illegal_argument_exception"


class TestMalformedBodiesNeverReach500:
    """A body the handler cannot use must be a vendor 400, not a crash.

    Found by probing every write route with a set of hostile bodies: seven
    routes answered a plain-text 500, which an integration cannot tell apart
    from the service falling over.
    """

    HOSTILE = [
        {"composite_ids": None},
        {"action_parameters": "x"},
        {"action_parameters": [None]},
        {"cases": [None]},
        {"query": {"bool": None}},
        {"query": []},
        {"size": "big"},
        {"from": "x"},
        {"Query": 5},
        [],
        "string",
    ]

    ROUTES = [
        ("PATCH", "/cs/alerts/entities/alerts/v3", "cs"),
        ("POST", "/cs/alerts/entities/alerts/v2", "cs"),
        ("PATCH", "/kibana/api/cases", "es"),
        ("POST", "/kibana/api/detection_engine/signals/search", "es"),
        ("POST", "/elastic/.siem-signals-default/_search", "es"),
        ("POST", "/mde/api/advancedqueries/run", "mde"),
        ("POST", "/splunk/services/saved/searches", "splunk"),
        ("POST", "/splunk/services/data/inputs/http", "splunk"),
        ("POST", "/splunk/services/data/indexes", "splunk"),
    ]

    @pytest.mark.parametrize(("method", "path", "vendor"), ROUTES)
    def test_no_hostile_body_produces_a_5xx(
        self, client: TestClient, method: str, path: str, vendor: str,
    ) -> None:
        headers = _vendor_headers(client, vendor)
        for body in self.HOSTILE:
            resp = client.request(method, path, json=body, headers=headers)
            assert resp.status_code < 500, (
                f"{method} {path} answered {resp.status_code} to {body!r}"
            )


def _vendor_headers(client: TestClient, vendor: str) -> dict[str, str]:
    """Authorization headers for the named vendor mount."""
    if vendor == "cs":
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    if vendor == "mde":
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    if vendor == "es":
        encoded = base64.b64encode(b"elastic:mock-elastic-password").decode()
        return {"Authorization": f"Basic {encoded}", "kbn-xsrf": "true"}
    encoded = base64.b64encode(b"admin:mockdr-admin").decode()
    return {"Authorization": f"Basic {encoded}"}
