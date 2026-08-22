"""Elasticsearch and Kibana behaviour, measured rather than assumed.

Every expectation here was taken from a running Elasticsearch 8.15.0 and
Kibana 8.15.0 by the conformance harness in ``conformance/``. Where a
docstring quotes a body, that is the body the real product sent.

The harness found 55 disagreements on its first run and 0 after these
fixes. These tests keep it at 0 without needing the real products up.
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}


class TestSearchWithoutAnIndex:
    """``/_search`` on its own searches every index."""

    def test_the_route_exists_and_answers_the_hit_envelope(self, client: TestClient) -> None:
        """It was missing entirely, so ``POST /_search`` fell through to a 404."""
        resp = client.post("/elastic/_search", json={"size": 0}, headers=ES_AUTH)
        assert resp.status_code == 200
        body = resp.json()
        assert {"took", "timed_out", "_shards", "hits"} <= set(body)
        assert {"total", "successful", "skipped", "failed"} <= set(body["_shards"])
        assert set(body["hits"]["total"]) == {"value", "relation"}

    def test_get_works_too(self, client: TestClient) -> None:
        assert client.get("/elastic/_search", headers=ES_AUTH).status_code == 200


class TestMalformedQuery:
    """Elasticsearch 8.15, for ``{"query":{"not_a_real_clause":{}}}``::

        {"error": {"root_cause": [{"type": "parsing_exception",
                                   "reason": "unknown query [not_a_real_clause]",
                                   "line": 1, "col": 31}],
                   "type": "parsing_exception",
                   "reason": "unknown query [not_a_real_clause]",
                   "line": 1, "col": 31,
                   "caused_by": {"type": "named_object_not_found_exception",
                                 "reason": "[1:31] unknown field [not_a_real_clause]"}},
         "status": 400}
    """

    BODY = b'{"query":{"not_a_real_clause":{}}}'

    def _post(self, client: TestClient) -> dict:
        resp = client.post(
            "/elastic/_search", content=self.BODY,
            headers={**ES_AUTH, "Content-Type": "application/json"},
        )
        assert resp.status_code == 400, resp.text
        return resp.json()

    def test_it_is_a_parsing_exception_not_a_404(self, client: TestClient) -> None:
        """With no root route the body never reached the parser."""
        body = self._post(client)
        assert body["status"] == 400
        assert body["error"]["type"] == "parsing_exception"
        assert body["error"]["reason"] == "unknown query [not_a_real_clause]"

    def test_elasticsearch_8_wording(self, client: TestClient) -> None:
        """``no [query] registered for`` was 6.x; 8.x says ``unknown query``."""
        assert "registered" not in self._post(client)["error"]["reason"]

    def test_caused_by_is_present(self, client: TestClient) -> None:
        caused_by = self._post(client)["error"]["caused_by"]
        assert caused_by["type"] == "named_object_not_found_exception"
        assert caused_by["reason"] == "[1:31] unknown field [not_a_real_clause]"

    def test_the_position_is_where_the_parser_stood(self, client: TestClient) -> None:
        """Column 31 is the ``{`` that opens the value — not column 11, the key."""
        error = self._post(client)["error"]
        assert (error["line"], error["col"]) == (1, 31)
        assert (error["root_cause"][0]["line"], error["root_cause"][0]["col"]) == (1, 31)

    def test_the_position_follows_the_body_the_client_sent(self, client: TestClient) -> None:
        """Found in the bytes as sent, so a pretty-printed body reports its own layout."""
        resp = client.post(
            "/elastic/_search",
            content=b'{\n  "query": {\n    "not_a_real_clause": {}\n  }\n}',
            headers={**ES_AUTH, "Content-Type": "application/json"},
        )
        error = resp.json()["error"]
        assert (error["line"], error["col"]) == (3, 26)


class TestIndexNotFound:
    """``resource.type`` and ``resource.id`` are literal dotted keys, not nested."""

    def test_resource_keys_are_present_and_flat(self, client: TestClient) -> None:
        body = client.get("/elastic/no-such-index-conformance/_search", headers=ES_AUTH).json()
        error = body["error"]
        assert error["resource.type"] == "index_or_alias"
        assert error["resource.id"] == "no-such-index-conformance"
        assert "resource" not in error
        assert error["root_cause"][0]["resource.id"] == "no-such-index-conformance"


class TestUnauthenticatedChallenge:
    """Elasticsearch 8.15 with default security sends two challenges::

        WWW-Authenticate: Basic realm="security", charset="UTF-8"
        WWW-Authenticate: ApiKey

    and no ``Bearer``: the token service advertises itself only when enabled,
    which on a stock install without TLS it is not.
    """

    def test_basic_then_apikey_and_no_bearer(self, client: TestClient) -> None:
        resp = client.get("/elastic/_cluster/health")
        assert resp.status_code == 401
        challenge = resp.headers["www-authenticate"]
        assert challenge.startswith('Basic realm="security", charset="UTF-8"')
        assert "ApiKey" in challenge
        assert "Bearer" not in challenge


class TestKibanaXsrf:
    """The xsrf check is a platform pre-handler and answers in Boom, always::

        {"statusCode": 400, "error": "Bad Request",
         "message": "Request must contain a kbn-xsrf header."}
    """

    def test_boom_envelope_even_on_a_security_solution_route(
        self, client: TestClient,
    ) -> None:
        """It used to pick the envelope by path and send ``{status_code}`` here."""
        resp = client.post(
            "/kibana/api/detection_engine/rules", headers=ES_AUTH,
            json={"name": "c", "description": "p", "type": "query",
                  "severity": "low", "risk_score": 1},
        )
        assert resp.status_code == 400
        body = resp.json()
        assert body == {
            "statusCode": 400,
            "error": "Bad Request",
            "message": "Request must contain a kbn-xsrf header.",
        }
        assert "status_code" not in body


class TestKibanaSpaces:
    """Kibana 8.15's default space, exactly::

        {"id": "default", "name": "Default",
         "description": "This is your default space!",
         "color": "#00bfb3", "disabledFeatures": [], "_reserved": true}
    """

    def test_exactly_the_fields_kibana_sends(self, client: TestClient) -> None:
        """It carried ``color: null`` and empty ``initials``/``imageUrl``."""
        spaces = client.get("/kibana/api/spaces/space", headers=ES_AUTH).json()
        assert len(spaces) == 1
        assert set(spaces[0]) == {
            "id", "name", "description", "color", "disabledFeatures", "_reserved",
        }
        assert spaces[0]["color"] == "#00bfb3"


class TestKibanaStatus:
    """What ``/api/status`` says depends on who asks."""

    def test_anonymous_gets_only_the_overall_level(self, client: TestClient) -> None:
        """Kibana 8.15 unauthenticated: ``{"status":{"overall":{"level":"available"}}}``."""
        body = client.get("/kibana/api/status").json()
        assert body == {"status": {"overall": {"level": "available"}}}

    def test_a_known_user_gets_the_full_document(self, client: TestClient) -> None:
        body = client.get("/kibana/api/status", headers=ES_AUTH).json()
        assert {"name", "uuid", "version", "status", "metrics"} <= set(body)
        assert body["version"]["build_flavor"] == "traditional"
        assert "summary" in body["status"]["overall"]
