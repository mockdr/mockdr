"""``/export`` and the row output modes, measured against Splunk 10.4.2.

An export streams one JSON object per row, the last one saying so, and a
search with no rows at all is a single line saying only that — which is how
a client knows the stream ended rather than broke. mockdr sent nothing for
an empty search and never marked the end of a full one; it also ignored
`output_mode` in the form body, so `csv`, `xml` and `json_rows` all came
back as the json stream.

`json_rows` and `json_cols` are narrower than csv: a job's results and
events answer them, and the job itself and the collection call them an
*invalid* output mode — a third wording for the same kind of refusal.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
SEARCH = '| makeresults format=csv data="host,sev\nsrv-3,50\nsrv-2,40"'


@pytest.fixture(scope="module")
def client() -> TestClient:
    """A client against the seeded app."""
    with TestClient(app) as test_client:
        yield test_client


def export(client: TestClient, mode: str, search: str = SEARCH) -> tuple[int, str, str]:
    """Run an export, returning status, content type and body."""
    response = client.post(
        "/splunk/services/search/jobs/export", headers=AUTH,
        data={"search": search, "output_mode": mode},
    )
    return response.status_code, response.headers["content-type"], response.text


class TestExport:
    """The streaming search, in each mode it answers."""

    def test_json_streams_a_line_per_row(self, client: TestClient) -> None:
        _status, ctype, body = export(client, "json")
        assert ctype.startswith("application/json")
        lines = [json.loads(line) for line in body.strip().split("\n")]
        assert lines[0] == {"preview": False, "offset": 0,
                            "result": {"host": "srv-3", "sev": "50"}}
        # The last row says so, and the offsets count from zero.
        assert lines[1]["lastrow"] is True
        assert lines[1]["offset"] == 1

    def test_a_search_with_no_rows_is_one_line(self, client: TestClient) -> None:
        _status, _ctype, body = export(client, "json", "| makeresults count=0")
        assert json.loads(body.strip()) == {"preview": False, "lastrow": True}

    def test_json_rows_names_the_fields_once(self, client: TestClient) -> None:
        _status, _ctype, body = export(client, "json_rows")
        assert json.loads(body) == {
            "preview": False, "init_offset": 0, "messages": [],
            "fields": ["host", "sev"], "rows": [["srv-3", "50"], ["srv-2", "40"]],
        }

    def test_csv_is_the_csv_document(self, client: TestClient) -> None:
        _status, ctype, body = export(client, "csv")
        assert ctype.startswith("text/csv")
        # And it quotes the way splunkd quotes: `srv-3` has a dash, `50` does
        # not need quoting at all.
        assert body == 'host,sev\n"srv-3",50\n"srv-2",40\n'

    def test_xml_is_the_results_document(self, client: TestClient) -> None:
        _status, ctype, body = export(client, "xml")
        assert ctype.startswith("text/xml")
        assert body.startswith("<?xml version='1.0' encoding='UTF-8'?>\n<results preview='0'>")
        assert "<field>host</field>" in body

    def test_a_search_that_will_not_run_is_a_400(self, client: TestClient) -> None:
        status, _ctype, body = export(client, "json", "| nosuchcommand")
        assert status == 400
        assert "Unknown search command 'nosuchcommand'." in body


class TestRowModes:
    """Where `json_rows` and `json_cols` are served, and where they are not."""

    def dispatch(self, client: TestClient) -> str:
        return client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": SEARCH, "output_mode": "json", "exec_mode": "blocking"},
        ).json()["sid"]

    def test_results_answer_json_rows(self, client: TestClient) -> None:
        sid = self.dispatch(client)
        body = client.get(f"/splunk/services/search/jobs/{sid}/results", headers=AUTH,
                          params={"output_mode": "json_rows"}).json()
        assert body["fields"] == ["host", "sev"]
        assert body["rows"] == [["srv-3", "50"], ["srv-2", "40"]]

    def test_and_json_cols_turns_it_on_its_side(self, client: TestClient) -> None:
        sid = self.dispatch(client)
        body = client.get(f"/splunk/services/search/jobs/{sid}/results", headers=AUTH,
                          params={"output_mode": "json_cols"}).json()
        assert body["columns"] == [["srv-3", "srv-2"], ["50", "40"]]

    def test_a_generating_search_matched_no_events(self, client: TestClient) -> None:
        # `| makeresults` reads no index, so `/events` is empty — where the
        # mock used to answer with the rows the pipeline produced.
        sid = self.dispatch(client)
        body = client.get(f"/splunk/services/search/jobs/{sid}/events", headers=AUTH,
                          params={"output_mode": "json_rows"}).json()
        assert body["fields"] == []
        assert body["rows"] == []

    def test_the_job_itself_calls_it_invalid(self, client: TestClient) -> None:
        sid = self.dispatch(client)
        response = client.get(f"/splunk/services/search/jobs/{sid}", headers=AUTH,
                              params={"output_mode": "json_rows"})
        assert response.status_code == 400
        assert response.json() == {
            "messages": [{"type": "FATAL", "text": "Invalid output_mode."}],
        }

    def test_and_so_does_the_collection(self, client: TestClient) -> None:
        response = client.get("/splunk/services/search/jobs", headers=AUTH,
                              params={"output_mode": "json_cols", "count": 1})
        assert response.status_code == 400
        assert response.json()["messages"][0]["text"] == "Invalid output_mode."

    def test_everywhere_else_it_is_unsupported(self, client: TestClient) -> None:
        response = client.get("/splunk/services/apps/local", headers=AUTH,
                              params={"output_mode": "json_rows", "count": 1})
        assert response.status_code == 400
        # A JSON mode is refused in JSON, where `atom` and `raw` are refused
        # in XML.
        assert response.json()["messages"] == [{
            "type": "WARN",
            "text": "Output mode 'json_rows' is not supported for this endpoint.",
        }]


class TestResultsXml:
    """The XML results document, which had no fields at all."""

    def test_it_names_its_fields_and_numbers_its_results(
        self, client: TestClient,
    ) -> None:
        response = client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": SEARCH, "output_mode": "xml", "exec_mode": "oneshot"},
        )
        assert response.text == (
            "<?xml version='1.0' encoding='UTF-8'?>\n\n"
            "<results preview='0'>\n<meta>\n<fieldOrder>\n"
            "<field>host</field>\n<field>sev</field>\n</fieldOrder>\n</meta>\n"
            "\t<result offset='0'>\n\t\t<field k='host'>\n"
            "\t\t\t<value><text>srv-3</text></value>\n\t\t</field>\n"
            "\t\t<field k='sev'>\n\t\t\t<value><text>50</text></value>\n\t\t</field>\n"
            "\t</result>\n"
            "\t<result offset='1'>\n\t\t<field k='host'>\n"
            "\t\t\t<value><text>srv-2</text></value>\n\t\t</field>\n"
            "\t\t<field k='sev'>\n\t\t\t<value><text>40</text></value>\n\t\t</field>\n"
            "\t</result>\n</results>\n"
        )

    def test_nothing_to_show_is_an_empty_element(self, client: TestClient) -> None:
        response = client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": "| makeresults count=0", "output_mode": "xml",
                  "exec_mode": "oneshot"},
        )
        assert response.text == (
            "<?xml version='1.0' encoding='UTF-8'?>\n\n<results preview='0'/>"
        )

    def test_a_multivalue_field_repeats_its_value(self, client: TestClient) -> None:
        response = client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": '| makeresults | eval m=split("a;b",";") | table m',
                  "output_mode": "xml", "exec_mode": "oneshot"},
        )
        assert "<value><text>a</text></value>\n\t\t\t<value><text>b</text></value>" in (
            response.text
        )
