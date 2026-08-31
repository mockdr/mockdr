"""`default` is where things go by default, not somewhere they go.

The simple receiver stored the word `default` as the index name, so an
event ingested through it was findable only by `search index=default` — a
name splunkd has no index for. A client that ingests and then searches the
index the event actually lives in, which is the whole point of the round
trip, found nothing and was told so with a successful, empty search.

Measured on 10.4.2. `POST /services/receivers/simple?index=default` comes
back echoing `_index: default`; the event is then found by
`search index=main`, and `search index=default | stats count` answers 0.

The event collector next door does *not* share this: it holds `default`
against the token's index list like any other name and answers
`{"text": "Incorrect index", "code": 7}` — which mockdr already did, and
which the last test here keeps true.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}  # admin:mockdr-admin
SIMPLE = "/splunk/services/receivers/simple"


def _count(client: TestClient, search: str) -> int:
    resp = client.post("/splunk/services/search/jobs", headers=AUTH,
                       data={"search": search, "exec_mode": "oneshot"})
    assert resp.status_code == 200, resp.text
    results = resp.json().get("results") or [{"count": "0"}]
    return int(results[0].get("count", 0))


class TestWhereASimplyReceivedEventLands:
    def test_it_lands_in_main_and_the_receipt_says_default(
        self, client: TestClient,
    ) -> None:
        before = _count(client, "search index=main sourcetype=probe-simple | stats count")

        resp = client.post(SIMPLE, headers=AUTH, content=b"a probe event",
                           params={"index": "default", "sourcetype": "probe-simple"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["index"] == "default"

        assert _count(
            client, "search index=main sourcetype=probe-simple | stats count",
        ) == before + 1
        assert _count(client, "search index=default | stats count") == 0

    def test_the_same_without_naming_an_index(self, client: TestClient) -> None:
        """`default` is also the parameter's own default."""
        before = _count(client, "search index=main sourcetype=probe-bare | stats count")
        resp = client.post(SIMPLE, headers=AUTH, content=b"another probe",
                           params={"sourcetype": "probe-bare"})
        assert resp.status_code == 200, resp.text
        assert _count(
            client, "search index=main sourcetype=probe-bare | stats count",
        ) == before + 1

    def test_a_named_index_is_still_the_index_named(
        self, client: TestClient,
    ) -> None:
        before = _count(client, "search index=notable sourcetype=probe-named | stats count")
        resp = client.post(SIMPLE, headers=AUTH, content=b"third probe",
                           params={"index": "notable", "sourcetype": "probe-named"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["index"] == "notable"
        assert _count(
            client, "search index=notable sourcetype=probe-named | stats count",
        ) == before + 1

    def test_an_index_that_does_not_exist_is_still_refused(
        self, client: TestClient,
    ) -> None:
        resp = client.post(SIMPLE, headers=AUTH, content=b"fourth probe",
                           params={"index": "nosuchindex"})
        assert resp.status_code == 400
        assert resp.json()["messages"] == [
            {"type": "WARN", "text": "supplied index 'nosuchindex' missing"}]


class TestTheCollectorDoesNotShareThis:
    def test_hec_holds_default_against_the_token_list(
        self, client: TestClient,
    ) -> None:
        entries = client.get("/splunk/services/data/inputs/http",
                             headers=AUTH).json()["entry"]
        token = entries[0]["content"]["token"]
        resp = client.post(
            "/splunk/services/collector/event",
            headers={"Authorization": f"Splunk {token}"},
            content=b'{"event":"x","index":"default"}')
        assert resp.status_code == 400
        assert resp.json()["text"] == "Incorrect index"
        assert resp.json()["code"] == 7


class TestTheMockAgreesWithItselfAboutNotable:
    """`search index=notable` was served from the notable store alone.

    So an event the receiver accepted with `?index=notable`, and which
    `stats count by index` then reported under that index, could not be
    found by `search index=notable` — the mock disagreeing with itself
    about where it had just put something.
    """

    def test_an_ingested_event_joins_the_seeded_notables(
        self, client: TestClient,
    ) -> None:
        seeded = _count(client, "search index=notable | stats count")
        assert seeded > 1, "no seeded notables; nothing to join"

        resp = client.post(SIMPLE, headers=AUTH, content=b"a notable probe",
                           params={"index": "notable", "sourcetype": "probe-nb"})
        assert resp.status_code == 200, resp.text

        assert _count(client, "search index=notable | stats count") == seeded + 1
        assert _count(
            client, "search index=notable sourcetype=probe-nb | stats count") == 1
        # And the seeded ones are still there, under their own sourcetype.
        assert _count(
            client, "search index=notable sourcetype=stash | stats count") == seeded

    def test_the_index_a_search_reports_is_the_index_it_searches(
        self, client: TestClient,
    ) -> None:
        """The two answers that disagreed, asked side by side."""
        client.post(SIMPLE, headers=AUTH, content=b"another notable probe",
                    params={"index": "notable", "sourcetype": "probe-nc"})
        by_index = _count(
            client, "search sourcetype=probe-nc | stats count by index")
        by_search = _count(
            client, "search index=notable sourcetype=probe-nc | stats count")
        assert by_index == by_search == 1
