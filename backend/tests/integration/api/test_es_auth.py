"""Integration tests for Elastic Security authentication endpoints.

Verifies Basic Auth, API Key auth, the OAuth2 token endpoint, RBAC,
and response structure against the real Elastic Security API contract.
"""
import base64

from fastapi.testclient import TestClient

# ── Auth helpers ──────────────────────────────────────────────────────────────

ES_BASIC_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}

ES_VIEWER_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"viewer:mock-viewer-password").decode(),
}

ES_ANALYST_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"analyst:mock-analyst-password").decode(),
}

# Pre-seeded admin API key: id=es-admin-key-001, api_key=mock-es-admin-api-key
ES_APIKEY_AUTH = {
    "Authorization": "ApiKey " + base64.b64encode(b"es-admin-key-001:mock-es-admin-api-key").decode(),
}

ES_VIEWER_APIKEY_AUTH = {
    "Authorization": "ApiKey " + base64.b64encode(b"es-viewer-key-001:mock-es-viewer-api-key").decode(),
}


class TestEsBasicAuth:
    """Tests for Elastic Security Basic Authentication."""

    def test_valid_basic_auth_returns_200(self, client: TestClient) -> None:
        """Valid Basic Auth credentials should access a protected endpoint."""
        resp = client.get("/elastic/", headers=ES_BASIC_AUTH)
        assert resp.status_code == 200

    def test_invalid_basic_auth_returns_401(self, client: TestClient) -> None:
        """Invalid password should return 401."""
        bad_auth = {
            "Authorization": "Basic " + base64.b64encode(b"elastic:wrong-password").decode(),
        }
        resp = client.get("/elastic/", headers=bad_auth)
        assert resp.status_code == 401

    def test_unknown_user_returns_401(self, client: TestClient) -> None:
        """Unknown username in Basic Auth should return 401."""
        bad_auth = {
            "Authorization": "Basic " + base64.b64encode(b"nobody:anything").decode(),
        }
        resp = client.get("/elastic/", headers=bad_auth)
        assert resp.status_code == 401

    def test_malformed_basic_value_returns_401(self, client: TestClient) -> None:
        """Non-base64 value after 'Basic ' should return 401."""
        resp = client.get("/elastic/", headers={"Authorization": "Basic %%%not-base64%%%"})
        assert resp.status_code == 401

    def test_missing_auth_header_returns_401(self, client: TestClient) -> None:
        """No Authorization header should return 401."""
        resp = client.get("/elastic/")
        assert resp.status_code == 401

    def test_wrong_scheme_returns_401(self, client: TestClient) -> None:
        """Bearer scheme (instead of Basic/ApiKey) should return 401."""
        resp = client.get("/elastic/", headers={"Authorization": "Bearer some-token"})
        assert resp.status_code == 401

    def test_analyst_basic_auth_returns_200(self, client: TestClient) -> None:
        """Analyst credentials should authenticate successfully."""
        resp = client.get("/elastic/", headers=ES_ANALYST_AUTH)
        assert resp.status_code == 200

    def test_viewer_basic_auth_returns_200(self, client: TestClient) -> None:
        """Viewer credentials should authenticate successfully on read endpoints."""
        resp = client.get("/elastic/", headers=ES_VIEWER_AUTH)
        assert resp.status_code == 200


class TestEsApiKeyAuth:
    """Tests for Elastic Security API Key authentication."""

    def test_valid_api_key_returns_200(self, client: TestClient) -> None:
        """Valid pre-seeded API key should access a protected endpoint."""
        resp = client.get("/elastic/", headers=ES_APIKEY_AUTH)
        assert resp.status_code == 200

    def test_invalid_api_key_returns_401(self, client: TestClient) -> None:
        """Invalid API key secret should return 401."""
        bad_auth = {
            "Authorization": "ApiKey " + base64.b64encode(b"es-admin-key-001:wrong-secret").decode(),
        }
        resp = client.get("/elastic/", headers=bad_auth)
        assert resp.status_code == 401

    def test_unknown_key_id_returns_401(self, client: TestClient) -> None:
        """Non-existent key ID should return 401."""
        bad_auth = {
            "Authorization": "ApiKey " + base64.b64encode(b"nonexistent-key:some-secret").decode(),
        }
        resp = client.get("/elastic/", headers=bad_auth)
        assert resp.status_code == 401

    def test_viewer_api_key_returns_200(self, client: TestClient) -> None:
        """Viewer API key should authenticate successfully on read endpoints."""
        resp = client.get("/elastic/", headers=ES_VIEWER_APIKEY_AUTH)
        assert resp.status_code == 200


class TestEsTokenEndpoint:
    """Tests for POST /elastic/_security/oauth2/token."""

    def test_valid_credentials_return_200(self, client: TestClient) -> None:
        """Valid username/password should return an access token."""
        resp = client.post("/elastic/_security/oauth2/token", json={
            "grant_type": "password",
            "username": "elastic",
            "password": "mock-elastic-password",
        })
        assert resp.status_code == 200

    def test_token_response_has_correct_fields(self, client: TestClient) -> None:
        """Token response must include access_token, type, and expires_in."""
        resp = client.post("/elastic/_security/oauth2/token", json={
            "grant_type": "password",
            "username": "elastic",
            "password": "mock-elastic-password",
        })
        body = resp.json()
        assert "access_token" in body
        assert isinstance(body["access_token"], str)
        assert len(body["access_token"]) > 0
        assert body["type"] == "Bearer"
        assert body["expires_in"] == 3600

    def test_invalid_credentials_return_401(self, client: TestClient) -> None:
        """Wrong password should return 401."""
        resp = client.post("/elastic/_security/oauth2/token", json={
            "grant_type": "password",
            "username": "elastic",
            "password": "wrong-password",
        })
        assert resp.status_code == 401

    def test_unknown_user_return_401(self, client: TestClient) -> None:
        """Non-existent username should return 401."""
        resp = client.post("/elastic/_security/oauth2/token", json={
            "grant_type": "password",
            "username": "nobody",
            "password": "anything",
        })
        assert resp.status_code == 401

    def test_analyst_token_return_200(self, client: TestClient) -> None:
        """Analyst user should obtain a token successfully."""
        resp = client.post("/elastic/_security/oauth2/token", json={
            "grant_type": "password",
            "username": "analyst",
            "password": "mock-analyst-password",
        })
        assert resp.status_code == 200
        assert "access_token" in resp.json()


class TestEsRbac:
    """Tests for Elastic Security role-based access control."""

    def test_viewer_cannot_write_to_kibana(self, client: TestClient) -> None:
        """Viewer role should receive 403 on Kibana write endpoints."""
        headers = {**ES_VIEWER_AUTH, "kbn-xsrf": "true"}
        resp = client.post(
            "/kibana/api/detection_engine/rules",
            headers=headers,
            json={"name": "Test Rule", "type": "query", "risk_score": 50, "severity": "low"},
        )
        assert resp.status_code == 403

    def test_analyst_can_write_to_kibana(self, client: TestClient) -> None:
        """Analyst role should be able to create rules."""
        headers = {**ES_ANALYST_AUTH, "kbn-xsrf": "true"}
        resp = client.post(
            "/kibana/api/detection_engine/rules",
            headers=headers,
            json={
                "name": "Analyst Rule", "description": "by analyst",
                "type": "query", "query": "*", "risk_score": 30, "severity": "low",
            },
        )
        assert resp.status_code == 200

    def test_viewer_api_key_cannot_write(self, client: TestClient) -> None:
        """Viewer API key should receive 403 on write endpoints."""
        headers = {**ES_VIEWER_APIKEY_AUTH, "kbn-xsrf": "true"}
        resp = client.post(
            "/kibana/api/detection_engine/rules",
            headers=headers,
            json={"name": "Should Fail", "type": "query", "risk_score": 50, "severity": "low"},
        )
        assert resp.status_code == 403


class TestErrorEnvelopeConformance:
    """Elasticsearch and Kibana ship together but do not share error shapes."""

    def test_elasticsearch_401_offers_www_authenticate(self, client: TestClient) -> None:
        """The challenge belongs in the real header, not only the body.

        A client following RFC 7235 reads the header to decide which scheme to
        retry with; without it there is nothing to act on.
        """
        resp = client.post("/elastic/logs-endpoint/_search", json={})
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers
        assert 'Basic realm="security"' in resp.headers["WWW-Authenticate"]

        error = resp.json()["error"]
        assert error["type"] == "security_exception"
        # Elasticsearch 8.15 with default security: Basic, then ApiKey, and no
        # Bearer — the token service only advertises itself when enabled.
        # Measured by the conformance harness against the real product.
        challenges = error["header"]["WWW-Authenticate"]
        assert challenges[0].startswith('Basic realm="security"')
        assert "ApiKey" in challenges
        assert not any("Bearer" in c for c in challenges)
        # Present on the root cause as well as the top-level error.
        assert error["root_cause"][0]["type"] == "security_exception"

    def test_elasticsearch_401_names_the_request_path(self, client: TestClient) -> None:
        resp = client.post("/elastic/logs-endpoint/_search", json={})
        assert "[/elastic/logs-endpoint/_search]" in resp.json()["error"]["reason"]

    def test_kibana_401_uses_the_boom_envelope(self, client: TestClient) -> None:
        """Kibana answers through Hapi/Boom: statusCode + error title + message."""
        resp = client.get("/kibana/api/cases/_find")
        assert resp.status_code == 401
        body = resp.json()
        assert body["statusCode"] == 401
        assert body["error"] == "Unauthorized"
        assert isinstance(body["error"], str), "Kibana's `error` is a title, not an object"
        assert "message" in body
        assert "root_cause" not in body

    def test_kibana_404_uses_the_boom_envelope(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/cases/no-such-case", headers=ES_BASIC_AUTH)
        assert resp.status_code == 404
        assert resp.json()["statusCode"] == 404
        assert resp.json()["error"] == "Not Found"

    def test_kibana_does_not_offer_www_authenticate(self, client: TestClient) -> None:
        """That challenge is an Elasticsearch behaviour, not a Kibana one."""
        resp = client.get("/kibana/api/cases/_find")
        assert "WWW-Authenticate" not in resp.headers

    def test_kbn_version_satisfies_the_xsrf_check(self, client: TestClient) -> None:
        """Kibana's guard passes when either header is present."""
        resp = client.post(
            "/kibana/api/cases",
            headers={**ES_BASIC_AUTH, "kbn-version": "8.19.0"},
            json={"title": "x", "description": "y"},
        )
        assert resp.status_code != 400

    def test_missing_xsrf_is_400_with_boom_envelope(self, client: TestClient) -> None:
        resp = client.post(
            "/kibana/api/cases", headers=ES_BASIC_AUTH, json={"title": "x"},
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body["statusCode"] == 400
        assert body["message"] == "Request must contain a kbn-xsrf header."
