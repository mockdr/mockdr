"""The simple receiver, the time parser, typeahead and the KV store's status.

Four endpoints an endpoint sweep found answering 404 here and 200 on Splunk
10.4.2 — and all four are things a client does *before* it trusts the rest:
it ingests through the simple receiver (the pre-HEC way, still in every
ad-hoc script), asks what a time modifier resolves to, completes a term, and
checks that the KV store is ready.

Measured against 10.4.2, refusals included: an index that is not there is a
WARN naming it, an empty body is "empty body", and a time modifier splunkd
cannot read is "Invalid time."
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
JSON = {"output_mode": "json"}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """A client against the seeded app."""
    with TestClient(app) as test_client:
        yield test_client


class TestSimpleReceiver:
    """The other way in."""

    def test_it_reports_what_it_wrote(self, client: TestClient) -> None:
        response = client.post(
            "/splunk/services/receivers/simple", headers=AUTH, content=b"probe body",
            params={**JSON, "index": "main", "sourcetype": "probe:simple",
                    "host": "probe-host", "source": "probe-source"},
        )
        assert response.status_code == 200
        assert response.json() == {
            "index": "main", "bytes": 10, "host": "probe-host",
            "source": "probe-source", "sourcetype": "probe:simple",
        }

    def test_the_event_is_then_searchable(self, client: TestClient) -> None:
        client.post(
            "/splunk/services/receivers/simple", headers=AUTH,
            content=b"receiver-probe-event", params={**JSON, "index": "main",
                                                    "sourcetype": "probe:searchable"},
        )
        body = client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": "search index=main sourcetype=probe:searchable | head 1",
                  "output_mode": "json", "exec_mode": "oneshot"},
        ).json()
        assert body["results"][0]["_raw"] == "receiver-probe-event"

    def test_what_it_stamps_when_it_is_told_nothing(self, client: TestClient) -> None:
        body = client.post(
            "/splunk/services/receivers/simple", headers=AUTH, content=b"x",
            params=JSON,
        ).json()
        # splunkd's own words for a payload it could not guess a sourcetype
        # from, and the source it gives a body that arrived over HTTP.
        assert body["sourcetype"] == "unknown-too_small"
        assert body["source"] == "http-simple"
        assert body["index"] == "default"

    def test_an_index_that_is_not_there_is_refused(self, client: TestClient) -> None:
        response = client.post(
            "/splunk/services/receivers/simple", headers=AUTH, content=b"x",
            params={**JSON, "index": "no-such-index"},
        )
        assert response.status_code == 400
        assert response.json()["messages"] == [
            {"type": "WARN", "text": "supplied index 'no-such-index' missing"},
        ]

    def test_an_empty_body_is_refused(self, client: TestClient) -> None:
        response = client.post(
            "/splunk/services/receivers/simple", headers=AUTH, content=b"",
            params={**JSON, "index": "main"},
        )
        assert response.status_code == 400
        assert response.json()["messages"][0]["text"] == "empty body"


class TestTimeParser:
    """What a modifier resolves to, which a dashboard shows before searching."""

    def test_a_modifier_answers_under_its_own_name(self, client: TestClient) -> None:
        body = client.get("/splunk/services/search/timeparser", headers=AUTH,
                          params={**JSON, "time": "-1d@d"}).json()
        assert list(body) == ["-1d@d"]
        assert body["-1d@d"].endswith("+00:00")

    def test_now_resolves_too(self, client: TestClient) -> None:
        body = client.get("/splunk/services/search/timeparser", headers=AUTH,
                          params={**JSON, "time": "now"}).json()
        assert "now" in body

    def test_a_modifier_it_cannot_read_is_refused(self, client: TestClient) -> None:
        response = client.get("/splunk/services/search/timeparser", headers=AUTH,
                              params={**JSON, "time": "-1x"})
        assert response.status_code == 400
        assert response.json()["messages"] == [{"type": "FATAL", "text": "Invalid time."}]

    def test_and_so_is_asking_about_two_at_once(self, client: TestClient) -> None:
        response = client.get(
            "/splunk/services/search/timeparser", headers=AUTH,
            params=[("time", "-1d@d"), ("time", "now"), ("output_mode", "json")],
        )
        assert response.status_code == 400


class TestTypeahead:
    """Completing a term from what the events carry."""

    def results(self, client: TestClient, prefix: str) -> list[dict]:
        return client.get("/splunk/services/search/typeahead", headers=AUTH,
                          params={**JSON, "prefix": prefix, "count": 5}).json()["results"]

    def test_an_index_prefix_lists_indexes(self, client: TestClient) -> None:
        results = self.results(client, "index=")
        assert results
        assert all(r["content"].startswith('index="') for r in results)
        # splunkd marks an index as an operator, and the other fields not.
        assert all(r["operator"] is True for r in results)

    def test_a_sourcetype_prefix_counts_the_events(self, client: TestClient) -> None:
        results = self.results(client, "sourcetype=")
        assert results
        assert all(r["operator"] is False for r in results)
        assert any(r["count"] > 0 for r in results)

    def test_a_partial_value_narrows_it(self, client: TestClient) -> None:
        results = self.results(client, "index=mai")
        assert [r["content"] for r in results] == ['index="main"']

    @pytest.mark.parametrize("prefix", ["sear", "| stats", ""])
    def test_anything_else_completes_nothing(
        self, client: TestClient, prefix: str,
    ) -> None:
        assert self.results(client, prefix) == []


class TestKvStoreStatus:
    """What a client checks before trusting the KV store."""

    def test_it_reports_itself_ready(self, client: TestClient) -> None:
        body = client.get("/splunk/services/kvstore/status", headers=AUTH,
                          params=JSON).json()
        content = body["entry"][0]["content"]
        assert content["current"]["status"] == "ready"
        assert content["current"]["replicationStatus"] == "KV store captain"

    def test_one_member_which_is_its_own_captain(self, client: TestClient) -> None:
        body = client.get("/splunk/services/kvstore/status", headers=AUTH,
                          params=JSON).json()
        members = body["entry"][0]["content"]["members"]
        assert list(members) == ["0"]
        assert members["0"]["hostAndPort"] == "127.0.0.1:8191"


class TestTypeaheadOutputModes:
    """The one endpoint whose default output mode is csv."""

    def test_without_output_mode_it_answers_csv(self, client: TestClient) -> None:
        response = client.get("/splunk/services/search/typeahead", headers=AUTH,
                              params={"prefix": "index=mai", "count": 2})
        assert response.headers["content-type"].startswith("text/csv")
        # A boolean keeps its JSON spelling in the CSV, not 1/0.
        assert response.text == 'content,count,operator\n"index=""main""",0,true\n'

    def test_nothing_to_complete_is_204(self, client: TestClient) -> None:
        response = client.get("/splunk/services/search/typeahead", headers=AUTH,
                              params={"prefix": "index=zzz", "count": 2})
        assert response.status_code == 204
        assert response.content == b""
        assert "content-type" not in response.headers

    def test_xml_is_the_results_document(self, client: TestClient) -> None:
        response = client.get("/splunk/services/search/typeahead", headers=AUTH,
                              params={"prefix": "index=mai", "count": 5,
                                      "output_mode": "xml"})
        # One newline under the declaration here, where a job's results have
        # two (both measured).
        assert response.text.startswith(
            "<?xml version='1.0' encoding='UTF-8'?>\n<results preview='0'>",
        )

    def test_atom_is_refused_like_anywhere_else(self, client: TestClient) -> None:
        response = client.get("/splunk/services/search/typeahead", headers=AUTH,
                              # `count` too, so the refusal under test is the
                              # output mode's and not the missing argument's.
                              params={"prefix": "index=mai", "count": 5,
                                      "output_mode": "atom"})
        assert response.status_code == 400
