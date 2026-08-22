"""Splunk management-API behaviour, measured rather than assumed.

Every expectation here was taken from a running Splunk 10.4.2 by the
conformance harness in ``conformance/``. The harness found 135 disagreements
on its first run over 16 probes; these tests keep the fixed ones fixed
without needing Splunk up. Where a docstring quotes a body, that is the body
splunkd sent.
"""
import base64

import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
HEC = "11111111-1111-1111-1111-111111111111"
J = {"output_mode": "json"}


class TestTwoKindsOf401:
    """splunkd refuses a bad password and a bad token in different shapes.

    No credentials, or wrong Basic ones::

        401  WWW-Authenticate: Basic realm="/splunk"
        {"messages":[{"type":"ERROR","text":"Unauthorized"}]}

    A session or Bearer token it does not recognise::

        401  (no challenge header)
        {"messages":[{"type":"WARN","text":"call not properly authenticated"}]}

    mockdr sent the second shape for every failure.
    """

    @pytest.mark.parametrize("headers", [
        {},
        {"Authorization": "Basic " + base64.b64encode(b"admin:wrong").decode()},
    ])
    def test_missing_or_wrong_password_is_unauthorized_with_a_challenge(
        self, client: TestClient, headers: dict,
    ) -> None:
        resp = client.get("/splunk/services/server/status", params=J, headers=headers)
        assert resp.status_code == 401
        assert resp.json() == {"messages": [{"type": "ERROR", "text": "Unauthorized"}]}
        assert resp.headers["www-authenticate"] == 'Basic realm="/splunk"'

    @pytest.mark.parametrize("scheme", ["Splunk", "Bearer"])
    def test_a_bad_token_is_not_properly_authenticated_without_a_challenge(
        self, client: TestClient, scheme: str,
    ) -> None:
        resp = client.get(
            "/splunk/services/server/status", params=J,
            headers={"Authorization": f"{scheme} deadbeef"},
        )
        assert resp.status_code == 401
        assert resp.json()["messages"][0] == {
            "type": "WARN", "text": "call not properly authenticated",
        }
        assert "www-authenticate" not in resp.headers


class TestServerInfo:
    """Authenticated, complete, and in splunkd's entry shape."""

    def test_anonymous_is_refused(self, client: TestClient) -> None:
        """It was open 'for health checks'. splunkd's health endpoint is HEC's."""
        assert client.get("/splunk/services/server/info", params=J).status_code == 401

    def test_carries_every_key_splunk_10_reports(self, client: TestClient) -> None:
        content = client.get(
            "/splunk/services/server/info", params=J, headers=AUTH,
        ).json()["entry"][0]["content"]
        # A representative sample of the thirty-five that were missing.
        for key in ("kvStoreStatus", "health_info", "host_fqdn", "numberOfCores",
                    "physicalMemoryMB", "startup_time", "manager_uri", "fips_mode"):
            assert key in content, key

    def test_entry_shape(self, client: TestClient) -> None:
        """Only `alternate` and `list` links, no `fields`, and no `create` offered."""
        body = client.get("/splunk/services/server/info", params=J, headers=AUTH).json()
        assert body["links"] == {}
        entry = body["entry"][0]
        assert set(entry["links"]) == {"alternate", "list"}
        assert "fields" not in entry


class TestSearchParser:
    """``POST /services/search/parser``: a flat object, not an Atom envelope.

    For ``search index=x | stats count by host | head 5`` splunkd answers
    ``commands`` with one entry per stage carrying ``pipeline`` and
    ``streamType``, plus ``eventsSearch``/``reportsSearch`` split at the
    first reporting command.
    """

    URL = "/splunk/services/search/parser"

    def test_search_parse_does_not_exist(self, client: TestClient) -> None:
        """mockdr served this path through 2.0.3. splunkd never did."""
        resp = client.post("/splunk/services/search/parse", data={"q": "search x"}, headers=AUTH)
        assert resp.status_code == 404

    def test_get_is_405_with_allow_post(self, client: TestClient) -> None:
        resp = client.get(self.URL, params={"q": "search x", **J}, headers=AUTH)
        assert resp.status_code == 405
        assert resp.headers["allow"] == "POST"
        assert resp.json() == {"messages": [{"type": "FATAL", "text": "The method is not allowed."}]}

    def test_answers_a_flat_object(self, client: TestClient) -> None:
        body = client.post(
            self.URL, data={"q": "search index=x | stats count by host | head 5", **J},
            headers=AUTH,
        ).json()
        assert "entry" not in body
        assert {"commands", "eventsSearch", "reportsSearch", "isStreamingSearch",
                "canSummarize", "normalizedSearch", "remoteSearch"} <= set(body)
        assert body["eventsSearch"] == "search index=x"
        assert body["reportsSearch"] == "stats count by host | head 5"
        assert body["isStreamingSearch"] is False

    def test_each_command_carries_its_pipeline_and_stream_type(
        self, client: TestClient,
    ) -> None:
        commands = client.post(
            self.URL, data={"q": "search index=x | stats count by host | head 5", **J},
            headers=AUTH,
        ).json()["commands"]
        by_name = {c["command"]: c for c in commands}
        assert by_name["search"]["isGenerating"] is True
        assert (by_name["search"]["pipeline"], by_name["search"]["streamType"]) == ("streaming", "SP_STREAM")
        assert (by_name["stats"]["pipeline"], by_name["stats"]["streamType"]) == ("report", "SP_STREAMREPORT")
        assert (by_name["head"]["pipeline"], by_name["head"]["streamType"]) == ("report", "SP_STATEFUL")

    def test_a_streaming_only_query(self, client: TestClient) -> None:
        body = client.post(self.URL, data={"q": "search index=x", **J}, headers=AUTH).json()
        assert body["isStreamingSearch"] is True
        assert body["reportsSearch"] == ""

    def test_unknown_command_is_fatal_with_splunks_wording(self, client: TestClient) -> None:
        resp = client.post(self.URL, data={"q": "search index=x | boguscmd y", **J}, headers=AUTH)
        assert resp.status_code == 400
        assert resp.json() == {
            "messages": [{"type": "FATAL", "text": "Unknown search command 'boguscmd'."}],
        }

    def test_empty_query_is_invalid(self, client: TestClient) -> None:
        resp = client.post(self.URL, data={"q": "", **J}, headers=AUTH)
        assert resp.status_code == 400
        assert resp.json() == {"messages": [{"type": "FATAL", "text": "Invalid query."}]}

    def test_v2_is_the_same_endpoint(self, client: TestClient) -> None:
        a = client.post(self.URL, data={"q": "search index=x", **J}, headers=AUTH).json()
        b = client.post(
            "/splunk/services/search/v2/parser", data={"q": "search index=x", **J}, headers=AUTH,
        ).json()
        assert a == b


class TestAppsLocal:
    """An app entry's ACL, links and content, as splunkd 10.4.2 shapes them."""

    def test_list_entry_shape(self, client: TestClient) -> None:
        entry = client.get("/splunk/services/apps/local", params=J, headers=AUTH).json()["entry"][0]
        assert set(entry["links"]) == {"alternate", "list", "_reload", "edit", "package"}
        assert "fields" not in entry
        assert {"can_change_perms", "can_share_app", "can_share_global", "can_share_user"} <= set(entry["acl"])
        content = entry["content"]
        assert "name" not in content
        assert {"check_for_updates", "configured", "core", "eai:acl",
                "managed_by_deployment_client", "show_in_nav",
                "state_change_requires_restart"} <= set(content)

    def test_single_app_carries_fields(self, client: TestClient) -> None:
        entry = client.get("/splunk/services/apps/local/search", params=J, headers=AUTH).json()["entry"][0]
        assert "upload_id" in entry["fields"]["optional"]

    def test_unknown_app_wording(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/apps/local/no_such_app", params=J, headers=AUTH)
        assert resp.status_code == 404
        assert resp.json()["messages"][0]["text"] == "Could not find object id=no_such_app"


class TestRefusalWording:
    """Texts a client may string-match, so they have to be splunkd's."""

    def test_unknown_endpoint_is_just_not_found(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/no/such/endpoint", params=J, headers=AUTH)
        assert resp.status_code == 404
        assert resp.json()["messages"][0]["text"] == "Not Found"

    def test_unknown_sid(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/search/jobs/0000000000.000000", params=J, headers=AUTH)
        assert resp.status_code == 404
        assert resp.json()["messages"][0]["text"] == "Unknown sid."

    def test_dispatch_without_a_query(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/search/jobs", params=J, headers=AUTH)
        assert resp.status_code == 400
        assert resp.json()["messages"][0]["text"].startswith(
            "The required 'search' parameter for the Splunk platform REST API search/jobs endpoint",
        )


class TestHecEventNumber:
    """``invalid-event-number`` is the zero-based position of the first
    failing event. Measured on Splunk 10.4.2::

        [bad, ok]        -> 0        [ok, bad]         -> 1
        [ok, ok, bad]    -> 2        [bad, bad]        -> 0   (first wins)

    with one quirk, reproduced rather than corrected: code 7 reports one
    higher than the others for the same position — a single event with a
    disallowed index says 1, ``[ok, bad-index]`` says 2. Request-level
    failures carry no key at all.
    """

    H = {"Authorization": f"Splunk {HEC}"}

    def _post(self, client: TestClient, content: str) -> dict:
        return client.post("/splunk/services/collector", headers=self.H, content=content).json()

    @pytest.mark.parametrize(("content", "code"), [
        ('{"sourcetype":"x"}', 12),
        ('{"event":""}', 13),
        ("{not json", 6),
    ])
    def test_a_single_bad_event_is_at_position_zero(
        self, client: TestClient, content: str, code: int,
    ) -> None:
        body = self._post(client, content)
        assert (body["code"], body["invalid-event-number"]) == (code, 0)

    def test_code_7_is_one_higher(self, client: TestClient) -> None:
        """The seeded token is restricted to one index; any other is code 7."""
        body = self._post(client, '{"event":"p","index":"no_such_index_conformance"}')
        assert (body["code"], body["invalid-event-number"]) == (7, 1)

    @pytest.mark.parametrize(("content", "expected"), [
        ('{"event":"ok"}{"event":""}', (13, 1)),
        ('{"event":"ok"}{"event":"ok"}{"event":""}', (13, 2)),
        ('{"event":""}{"event":""}', (13, 0)),
        ('{"event":"ok"}{"event":"p","index":"no_such"}', (7, 2)),
        ('{"event":"ok"}{"event":"ok"}{"event":"p","index":"no_such"}', (7, 3)),
        ('{"event":"ok"}{not json', (6, 1)),
    ])
    def test_batch_positions(
        self, client: TestClient, content: str, expected: tuple[int, int],
    ) -> None:
        body = self._post(client, content)
        assert (body["code"], body["invalid-event-number"]) == expected

    @pytest.mark.parametrize(("content", "expected"), [
        ('{"event":""}{"event":"p","index":"no_such"}', (13, 0)),
        ('{"event":"p","index":"no_such"}{"event":""}', (7, 1)),
    ])
    def test_the_first_failure_in_document_order_wins(
        self, client: TestClient, content: str, expected: tuple[int, int],
    ) -> None:
        body = self._post(client, content)
        assert (body["code"], body["invalid-event-number"]) == expected

    @pytest.mark.parametrize("headers", [
        {}, {"Authorization": "Splunk 00000000-0000-0000-0000-000000000000"},
    ])
    def test_request_level_failures_carry_no_position(
        self, client: TestClient, headers: dict,
    ) -> None:
        resp = client.post("/splunk/services/collector", headers=headers, json={"event": "x"})
        assert "invalid-event-number" not in resp.json()

    def test_no_data_carries_no_position(self, client: TestClient) -> None:
        body = self._post(client, "   ")
        assert body["code"] == 5
        assert "invalid-event-number" not in body
