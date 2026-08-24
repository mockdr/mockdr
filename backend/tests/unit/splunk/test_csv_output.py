"""``output_mode=csv``, which splunkd serves on four paths and nowhere else.

Measured against Splunk 10.4.2: a job's ``results`` and ``events``, the job
itself and the job collection answer as CSV; every other endpoint refuses it
with ``Output mode 'csv' is not supported for this endpoint.``

The quoting is not RFC 4180's. splunkd writes a token bare only when it is
purely alphanumeric — ``ok`` and ``42`` bare, ``1.5`` and ``a-b`` and ``a b``
and ``a:b`` quoted — and a multivalue field becomes one quoted cell whose
members are separated by newlines.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app
from utils.splunk.csv_output import render_splunk_csv

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """A client against the seeded app."""
    with TestClient(app) as test_client:
        yield test_client


def results(rows: list[dict], fields: list[str] | None = None) -> dict:
    """A results envelope the way a Splunk router builds one."""
    body: dict = {"results": rows}
    if fields is not None:
        body["fields"] = [{"name": f} for f in fields]
    return body


class TestQuoting:
    """What splunkd writes bare, and what it wraps."""

    @pytest.mark.parametrize("value", ["ok", "42", "abc123", "A1"])
    def test_a_purely_alphanumeric_value_is_bare(self, value: str) -> None:
        assert render_splunk_csv(results([{"a": value}])) == f"a\n{value}\n"

    @pytest.mark.parametrize("value", ["1.5", "a-b", "a b", "a:b", "/x/y", "-3", "a~b", ""])
    def test_everything_else_is_quoted(self, value: str) -> None:
        # Far wider than RFC 4180, which would only quote a comma, a quote or
        # a newline — but it is the rule splunkd uses.
        assert render_splunk_csv(results([{"a": value}])) == f'a\n"{value}"\n'

    def test_a_comma_is_quoted(self) -> None:
        assert render_splunk_csv(results([{"a": "x,y"}])) == 'a\n"x,y"\n'

    def test_a_quote_is_doubled(self) -> None:
        assert render_splunk_csv(results([{"a": 'say "hi"'}])) == 'a\n"say ""hi"""\n'

    def test_a_multivalue_field_is_one_cell_of_newlines(self) -> None:
        assert render_splunk_csv(results([{"a": ["x", "y"]}])) == 'a\n"x\ny"\n'

    def test_a_field_the_row_has_no_value_for_is_empty(self) -> None:
        # Nothing at all between the commas, not `""` — which is what an
        # empty *string* renders as.
        assert render_splunk_csv(results([{"a": "1", "b": None}], ["a", "b"])) == "a,b\n1,\n"

    def test_the_header_follows_the_same_rule(self) -> None:
        rendered = render_splunk_csv(results([{"ab": "1", "a_b": "2"}], ["ab", "a_b"]))
        assert rendered.split("\n")[0] == 'ab,"a_b"'


class TestColumns:
    """Which columns appear, and in what order."""

    def test_the_declared_field_order_is_kept(self) -> None:
        # `results` keeps the order the search produced, unsorted.
        body = results([{"zz": "1", "aa": "2", "mm": "3"}], ["zz", "aa", "mm"])
        assert render_splunk_csv(body).split("\n")[0] == "zz,aa,mm"

    def test_events_sort_their_columns(self) -> None:
        body = results([{"zz": "1", "aa": "2"}], ["zz", "aa"])
        assert render_splunk_csv(body, sort_columns=True).split("\n")[0] == "aa,zz"

    def test_columns_are_taken_from_the_rows_when_none_are_declared(self) -> None:
        assert render_splunk_csv(results([{"a": "1"}, {"b": "2"}])).split("\n")[0] == "a,b"

    def test_a_row_missing_a_column_leaves_it_empty(self) -> None:
        assert render_splunk_csv(results([{"a": "1"}, {"b": "2"}])) == "a,b\n1,\n,2\n"

    def test_an_entry_collection_renders_its_content(self) -> None:
        body = {"entry": [{"name": "x", "content": {"a": "1", "b": "2"}}]}
        assert render_splunk_csv(body) == "a,b\n1,2\n"

    def test_nothing_to_render_is_an_empty_document(self) -> None:
        assert render_splunk_csv(results([])) == ""
        assert render_splunk_csv({"sid": "1"}) == ""


class TestOverTheWire:
    """Which endpoints answer, and with what content type."""

    def _oneshot(self, client: TestClient, search: str, mode: str = "csv") -> object:
        return client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": search, "output_mode": mode, "exec_mode": "oneshot"},
        )

    def test_a_oneshot_search_answers_as_csv(self, client: TestClient) -> None:
        response = self._oneshot(
            client, "search index=sentinelone | head 2 | table index, sourcetype",
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=UTF-8"
        # A oneshot puts a line for its messages before the header.
        lines = response.text.split("\n")
        assert lines[0].strip() == ""
        assert lines[1] == 'index,sourcetype'

    def test_a_dispatched_jobs_results_have_no_message_line(
        self, client: TestClient,
    ) -> None:
        sid = client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": "search index=sentinelone | head 1 | table index",
                  "output_mode": "json", "exec_mode": "blocking"},
        ).json()["sid"]
        response = client.get(
            f"/splunk/services/search/jobs/{sid}/results", headers=AUTH,
            params={"output_mode": "csv"},
        )
        assert response.status_code == 200
        assert response.text == "index\nsentinelone\n"

    def test_a_job_with_nothing_to_show_answers_empty_as_text(
        self, client: TestClient,
    ) -> None:
        sid = client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": "search index=no_such_index_xyz | table a",
                  "output_mode": "json", "exec_mode": "blocking"},
        ).json()["sid"]
        response = client.get(
            f"/splunk/services/search/jobs/{sid}/results", headers=AUTH,
            params={"output_mode": "csv"},
        )
        assert response.status_code == 200
        assert response.content == b""
        assert response.headers["content-type"] == "text/plain; charset=UTF-8"

    def test_the_job_collection_answers(self, client: TestClient) -> None:
        # A oneshot deletes its job when it is done, so dispatch one that stays.
        client.post(
            "/splunk/services/search/jobs", headers=AUTH,
            data={"search": "search index=sentinelone | head 1", "output_mode": "json",
                  "exec_mode": "blocking"},
        )
        response = client.get(
            "/splunk/services/search/jobs", headers=AUTH,
            params={"output_mode": "csv", "count": 1},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        # The columns are the job's own content keys.
        assert "sid" in response.text.split("\n")[0]

    @pytest.mark.parametrize("path", [
        "/splunk/services/saved/searches",
        "/splunk/services/data/indexes",
        "/splunk/services/apps/local",
        "/splunk/services/authentication/users",
    ])
    def test_every_other_endpoint_refuses_it(
        self, client: TestClient, path: str,
    ) -> None:
        response = client.get(path, headers=AUTH, params={"output_mode": "csv"})
        assert response.status_code == 400
        assert "Output mode 'csv' is not supported for this endpoint." in response.text
