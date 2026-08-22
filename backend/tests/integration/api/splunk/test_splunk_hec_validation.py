"""HEC request validation against Splunk's published error-code table.

mockdr answered ``Success`` to several bodies real HEC rejects, so a
misconfigured forwarder looked healthy, and raised through the handler on two
others, returning a plain-text 500 that is not even a HEC envelope.
"""
import pytest
from fastapi.testclient import TestClient

from repository.splunk.hec_token_repo import hec_token_repo

SPLUNK_PREFIX = "/splunk"
EVENT_URL = f"{SPLUNK_PREFIX}/services/collector/event"


@pytest.fixture
def hec_auth() -> dict[str, str]:
    """Authorization header for the seeded HEC token."""
    token = hec_token_repo.list_all()[0]
    return {"Authorization": f"Splunk {token.token}"}


def _post(client: TestClient, body: str, hec_auth: dict, **kwargs: object) -> tuple:
    resp = client.post(EVENT_URL, content=body, headers=hec_auth, **kwargs)
    return resp.status_code, resp.json()


class TestRejectedBodies:
    """Bodies real HEC refuses must not come back as Success."""

    @pytest.mark.parametrize(
        ("body", "code", "why"),
        [
            ('{"foo":"bar"}', 12, "no event field"),
            ('{"event":""}', 13, "blank event"),
            ('{"event":"   "}', 13, "whitespace-only event"),
            ('{"event":null}', 13, "null event"),
            ('{"event":"x","index":"no_such_index"}', 7, "index outside the token"),
            ('{"event":"x","time":"notanumber"}', 15, "non-numeric time"),
            ("not json at all", 6, "unparseable"),
            ("", 5, "empty body"),
        ],
    )
    def test_rejection(
        self, client: TestClient, hec_auth: dict, body: str, code: int, why: str,
    ) -> None:
        status, payload = _post(client, body, hec_auth)

        assert status == 400, f"{why} was accepted"
        assert payload["code"] == code
        assert isinstance(payload.get("text"), str)

    def test_rejection_is_a_hec_envelope_not_plain_text(
        self, client: TestClient, hec_auth: dict,
    ) -> None:
        # These two used to raise out of the handler as text/plain 500s.
        # A top-level array is a batch on splunkd (200), not a rejection.
        for body in ('{"event":"x","time":"nope"}', "{not json"):
            resp = client.post(EVENT_URL, content=body, headers=hec_auth)
            assert resp.status_code == 400
            assert resp.headers["content-type"].startswith("application/json")


class TestAcceptedBodies:
    """Bodies real HEC accepts must not be refused."""

    def test_single_event(self, client: TestClient, hec_auth: dict) -> None:
        status, payload = _post(client, '{"event":"hello"}', hec_auth)
        assert (status, payload["code"]) == (200, 0)

    def test_newline_delimited_events(self, client: TestClient, hec_auth: dict) -> None:
        status, payload = _post(client, '{"event":"a"}\n{"event":"b"}', hec_auth)
        assert (status, payload["code"]) == (200, 0)

    def test_concatenated_events(self, client: TestClient, hec_auth: dict) -> None:
        # HEC accepts objects run together with no separator; this was
        # rejected as invalid JSON.
        status, payload = _post(client, '{"event":"a"}{"event":"b"}', hec_auth)
        assert (status, payload["code"]) == (200, 0)

    def test_structured_event(self, client: TestClient, hec_auth: dict) -> None:
        status, payload = _post(client, '{"event":{"msg":"hi"},"time":1700000000}', hec_auth)
        assert (status, payload["code"]) == (200, 0)

    def test_fields_only_event(self, client: TestClient, hec_auth: dict) -> None:
        status, payload = _post(client, '{"fields":{"k":"v"}}', hec_auth)
        assert (status, payload["code"]) == (200, 0)


class TestIndexerAcknowledgement:
    """``useACK`` requires a channel and issues real ids."""

    def test_use_ack_without_a_channel_is_refused(
        self, client: TestClient, hec_auth: dict,
    ) -> None:
        status, payload = _post(
            client, '{"event":"x"}', hec_auth, params={"useACK": "true"},
        )
        assert status == 400
        assert payload["code"] == 10

    def test_use_ack_with_a_channel_returns_an_ack_id(
        self, client: TestClient, hec_auth: dict,
    ) -> None:
        resp = client.post(
            EVENT_URL,
            content='{"event":"x"}',
            headers={**hec_auth, "X-Splunk-Request-Channel": "chan-a"},
            params={"useACK": "true"},
        )
        assert resp.status_code == 200
        assert "ackId" in resp.json(), "the acknowledgement workflow needs an id"

    def test_ack_ids_are_distinct_per_submission(
        self, client: TestClient, hec_auth: dict,
    ) -> None:
        headers = {**hec_auth, "X-Splunk-Request-Channel": "chan-b"}
        first = client.post(
            EVENT_URL, content='{"event":"1"}', headers=headers,
            params={"useACK": "true"},
        ).json()["ackId"]
        second = client.post(
            EVENT_URL, content='{"event":"2"}', headers=headers,
            params={"useACK": "true"},
        ).json()["ackId"]

        assert first != second


class TestRawEndpoint:
    """``/raw`` has its own rules."""

    def test_empty_body_is_no_data(self, client: TestClient, hec_auth: dict) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/raw", content="", headers=hec_auth,
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == 5

    def test_text_body_is_accepted(self, client: TestClient, hec_auth: dict) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}/services/collector/raw",
            content="a raw line", headers=hec_auth,
        )
        assert resp.status_code == 200
        assert resp.json()["code"] == 0


class TestVersionedPaths:
    """The 1.0-suffixed aliases real HEC serves."""

    @pytest.mark.parametrize(
        "path",
        [
            "/services/collector/event/1.0",
            "/services/collector/raw/1.0",
            "/services/collector/1.0",
        ],
    )
    def test_alias_is_served(self, client: TestClient, hec_auth: dict, path: str) -> None:
        resp = client.post(
            f"{SPLUNK_PREFIX}{path}", content='{"event":"x"}', headers=hec_auth,
        )
        assert resp.status_code == 200

    def test_health_alias(self, client: TestClient) -> None:
        resp = client.get(f"{SPLUNK_PREFIX}/services/collector/health/1.0")
        assert resp.status_code == 200
        assert resp.json()["code"] == 17
