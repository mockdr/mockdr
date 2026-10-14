"""The XQL routes answer in the shapes and vocabulary Cortex XDR uses.

Sources, for every assertion below:

- Palo Alto, "Run XQL query APIs" (cortex-docs.paloaltonetworks.com):
  `start_xql_query` answers `{"reply": "<execution_id>"}`; `get_query_results`
  takes `pending_flag` (default true: return at once, `PENDING` while it runs;
  false: wait for the results) and `limit`, answers `status` as `PENDING`,
  `SUCCESS` or `FAIL`, at most 1,000 results inline and a `stream_id` above
  that; `get_quota` answers integers and a number.
- XSOAR CoreXQLApiModule (demisto/content): `execution_id = res.get("reply", "")`;
  polls while `status == "PENDING"`; reads `results.stream_id` and fetches
  `/xql/get_query_results_stream` with `is_gzip_compressed: true`, then
  `gzip.decompress(...)` split on newlines, one JSON object per line. Its
  tests mock replies such as `{"status": "SUCCESS", "number_of_results": 1,
  "query_cost": {...}, "remaining_quota": 1000.0, "results": {"data": [...]}}`.
"""
from __future__ import annotations

import gzip
import json

from fastapi.testclient import TestClient

from tests.integration.api.test_xdr_misc import XDR_PREFIX, _xdr_headers


def _start(client: TestClient, query: object = "dataset = xdr_data | limit 5") -> object:
    resp = client.post(
        f"{XDR_PREFIX}/xql/start_xql_query",
        json={"request_data": {"query": query}}, headers=_xdr_headers(),
    )
    return resp


def _results(client: TestClient, **request_data: object) -> dict:
    resp = client.post(
        f"{XDR_PREFIX}/xql/get_query_results",
        json={"request_data": request_data}, headers=_xdr_headers(),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["reply"]


class TestStartAnswersTheExecutionIdItself:
    """`reply` was `{"query_id": …}`; Cortex answers the id as a bare string.

    The XSOAR client takes `res.get("reply", "")` as the execution id and
    sends it back as `query_id`, so against the mock it sent a dict and every
    poll failed.
    """

    def test_reply_is_a_string_the_results_route_accepts(self, client: TestClient) -> None:
        resp = _start(client)
        assert resp.status_code == 200
        execution_id = resp.json()["reply"]
        assert isinstance(execution_id, str) and execution_id
        assert _results(client, query_id=execution_id, pending_flag=False)["status"] == "SUCCESS"

    def test_an_empty_query_is_refused(self, client: TestClient) -> None:
        """`query` is the route's one required member; "" is no query."""
        for query in ("", "   ", None, ["dataset = xdr_data"]):
            resp = _start(client, query)
            assert resp.status_code == 400, query
            assert resp.json()["reply"]["err_code"] == 400


class TestAQueryIdThatIsNotAStringIsA400:
    """A list `query_id` reached the store as a key and answered 500 (unhashable)."""

    def test_list_and_object_ids(self, client: TestClient) -> None:
        for bad in (["a"], {"a": 1}, 7, ""):
            resp = client.post(
                f"{XDR_PREFIX}/xql/get_query_results",
                json={"request_data": {"query_id": bad}}, headers=_xdr_headers(),
            )
            assert resp.status_code == 400, (bad, resp.text)
            assert resp.json()["reply"]["err_code"] == 400


class TestStatusVocabulary:
    """The mock answered `pending`/`completed`; Cortex answers `PENDING`/`SUCCESS`.

    XSOAR's poller compares against `"PENDING"` exactly, so a lower-case
    status ended the poll at once and a `completed` query was never
    recognised as done.
    """

    def test_a_poll_sees_pending_then_success(self, client: TestClient) -> None:
        execution_id = _start(client).json()["reply"]
        first = _results(client, query_id=execution_id, pending_flag=True)
        assert first["status"] == "PENDING"
        second = _results(client, query_id=execution_id, pending_flag=True)
        assert second["status"] == "SUCCESS"
        assert second["number_of_results"] == len(second["results"]["data"]) > 0

    def test_pending_flag_false_waits_for_the_results(self, client: TestClient) -> None:
        execution_id = _start(client).json()["reply"]
        reply = _results(client, query_id=execution_id, pending_flag=False)
        assert reply["status"] == "SUCCESS"
        assert reply["results"]["data"]

    def test_the_cost_and_quota_are_numbers(self, client: TestClient) -> None:
        execution_id = _start(client).json()["reply"]
        reply = _results(client, query_id=execution_id, pending_flag=False)
        assert isinstance(reply["remaining_quota"], float)
        assert all(isinstance(v, float) for v in reply["query_cost"].values())


class TestLimitIsHonoured:
    """`limit` was read by nobody, so a client asking for one row got them all."""

    def test_limit_caps_the_rows(self, client: TestClient) -> None:
        execution_id = _start(client).json()["reply"]
        reply = _results(client, query_id=execution_id, pending_flag=False, limit=1)
        assert len(reply["results"]["data"]) == 1

    def test_a_limit_that_is_not_a_number_is_a_400(self, client: TestClient) -> None:
        execution_id = _start(client).json()["reply"]
        resp = client.post(
            f"{XDR_PREFIX}/xql/get_query_results",
            json={"request_data": {"query_id": execution_id, "limit": "ten"}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 400


class TestMoreThanAThousandResultsComeAsAStream:
    """Above 1,000 results Cortex hands out a `stream_id`, not the rows.

    There was no stream and no `/xql/get_query_results_stream` route, so a
    client's large-result branch could not be exercised at all.
    """

    def test_stream_id_then_gzipped_ndjson(self, client: TestClient) -> None:
        from repository.xdr_xql_query_repo import xdr_xql_query_repo

        execution_id = _start(client).json()["reply"]
        _results(client, query_id=execution_id, pending_flag=False)
        query = xdr_xql_query_repo.get(execution_id)
        assert query is not None
        query.results = [{"n": i} for i in range(1500)]
        xdr_xql_query_repo.save(query)

        reply = _results(client, query_id=execution_id)
        assert reply["number_of_results"] == 1500
        stream_id = reply["results"]["stream_id"]
        assert not reply["results"].get("data")

        resp = client.post(
            f"{XDR_PREFIX}/xql/get_query_results_stream",
            json={"request_data": {"stream_id": stream_id, "is_gzip_compressed": True}},
            headers=_xdr_headers(),
        )
        assert resp.status_code == 200
        lines = gzip.decompress(resp.content).decode().split("\n")
        rows = [json.loads(line) for line in lines if line]
        assert len(rows) == 1500 and rows[0] == {"n": 0}


class TestQuotaIsNumbers:
    """`get_quota` answered `""` for the documented integer fields."""

    def test_documented_fields_are_numbers(self, client: TestClient) -> None:
        resp = client.post(
            f"{XDR_PREFIX}/xql/get_quota", json={"request_data": {}}, headers=_xdr_headers(),
        )
        reply = resp.json()["reply"]
        for key in (
            "license_quota", "additional_purchased_quota", "eval_quota",
            "current_concurrent_active_queries_count",
            "max_daily_concurrent_active_query_count",
            "total_daily_concurrent_rejected_queries", "total_daily_running_queries",
        ):
            assert isinstance(reply[key], int) and not isinstance(reply[key], bool), key
        assert isinstance(reply["used_quota"], float)
        assert isinstance(reply["current_concurrent_active_queries"], dict)
