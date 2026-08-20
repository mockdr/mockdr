"""Elasticsearch aggregations and the cluster APIs clients probe first.

``aggs`` was read past entirely — a body asking for a terms breakdown got a
normal hit list and no ``aggregations`` key at all, so a dashboard built on it
rendered empty rather than failing. And the ES surface was six routes, so
``_count``, ``_cat/indices``, ``_cluster/health`` and ``_mget`` — the calls a
client makes before it trusts a cluster — all 404'd.
"""
import base64

import pytest
from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}
INDEX = ".siem-signals-default"
SEARCH_URL = f"/elastic/{INDEX}/_search"


def _aggregate(client: TestClient, aggs: dict, **body: object) -> dict:
    resp = client.post(
        SEARCH_URL, json={"size": 0, "aggs": aggs, **body}, headers=ES_AUTH,
    )
    assert resp.status_code == 200, resp.text
    return dict(resp.json()["aggregations"])


class TestTermsAggregation:
    """The aggregation a SIEM dashboard reaches for first."""

    def test_returns_buckets(self, client: TestClient) -> None:
        result = _aggregate(
            client, {"by_sev": {"terms": {"field": "signal.rule.severity"}}},
        )
        buckets = result["by_sev"]["buckets"]

        assert buckets, "terms produced no buckets"
        assert {"key", "doc_count"} <= set(buckets[0])

    def test_carries_the_bookkeeping_fields(self, client: TestClient) -> None:
        result = _aggregate(
            client, {"by_sev": {"terms": {"field": "signal.rule.severity"}}},
        )
        assert "doc_count_error_upper_bound" in result["by_sev"]
        assert "sum_other_doc_count" in result["by_sev"]

    def test_doc_counts_sum_to_the_hit_total(self, client: TestClient) -> None:
        resp = client.post(
            SEARCH_URL,
            json={"size": 0, "aggs": {"s": {"terms": {
                "field": "signal.rule.severity", "size": 100,
            }}}},
            headers=ES_AUTH,
        ).json()

        counted = sum(b["doc_count"] for b in resp["aggregations"]["s"]["buckets"])
        assert counted == resp["hits"]["total"]["value"]

    def test_size_limits_buckets(self, client: TestClient) -> None:
        result = _aggregate(
            client, {"s": {"terms": {"field": "signal.rule.severity", "size": 1}}},
        )
        assert len(result["s"]["buckets"]) == 1
        assert result["s"]["sum_other_doc_count"] > 0

    def test_buckets_are_ordered_by_count(self, client: TestClient) -> None:
        result = _aggregate(
            client, {"s": {"terms": {"field": "signal.rule.severity", "size": 100}}},
        )
        counts = [b["doc_count"] for b in result["s"]["buckets"]]
        assert counts == sorted(counts, reverse=True)


class TestMetricAggregations:
    """Metrics over the matched set."""

    @pytest.mark.parametrize(
        "agg", ["min", "max", "avg", "sum", "cardinality", "value_count"],
    )
    def test_metric_returns_a_value(self, client: TestClient, agg: str) -> None:
        result = _aggregate(client, {"m": {agg: {"field": "signal.rule.risk_score"}}})
        assert "value" in result["m"]

    def test_stats_reports_every_member(self, client: TestClient) -> None:
        result = _aggregate(client, {"m": {"stats": {"field": "signal.rule.risk_score"}}})
        assert {"count", "min", "max", "avg", "sum"} == set(result["m"])

    def test_min_does_not_exceed_max(self, client: TestClient) -> None:
        result = _aggregate(client, {"m": {"stats": {"field": "signal.rule.risk_score"}}})
        assert result["m"]["min"] <= result["m"]["max"]

    def test_top_hits_returns_documents(self, client: TestClient) -> None:
        result = _aggregate(client, {"t": {"top_hits": {"size": 2}}})
        assert len(result["t"]["hits"]["hits"]) == 2


class TestBucketAggregations:
    """Histogram, range and filter buckets."""

    def test_date_histogram(self, client: TestClient) -> None:
        result = _aggregate(
            client,
            {"over_time": {"date_histogram": {
                "field": "@timestamp", "fixed_interval": "1d",
            }}},
        )
        buckets = result["over_time"]["buckets"]
        assert buckets
        assert "key_as_string" in buckets[0]

    def test_range(self, client: TestClient) -> None:
        result = _aggregate(client, {"r": {"range": {
            "field": "signal.rule.risk_score",
            "ranges": [{"to": 50}, {"from": 50}],
        }}})
        assert len(result["r"]["buckets"]) == 2

    def test_filter(self, client: TestClient) -> None:
        result = _aggregate(client, {"f": {"filter": {
            "term": {"signal.rule.severity": "low"},
        }}})
        assert "doc_count" in result["f"]

    def test_named_filters(self, client: TestClient) -> None:
        result = _aggregate(client, {"f": {"filters": {"filters": {
            "low": {"term": {"signal.rule.severity": "low"}},
            "high": {"term": {"signal.rule.severity": "high"}},
        }}}})
        assert set(result["f"]["buckets"]) == {"low", "high"}


class TestSubAggregations:
    """Aggregations nest, which is most of their value."""

    def test_metric_inside_terms(self, client: TestClient) -> None:
        result = _aggregate(client, {"by_sev": {
            "terms": {"field": "signal.rule.severity"},
            "aggs": {"avg_risk": {"avg": {"field": "signal.rule.risk_score"}}},
        }})
        bucket = result["by_sev"]["buckets"][0]

        assert "avg_risk" in bucket
        assert bucket["avg_risk"]["value"] is not None


class TestAggregationScope:
    """Aggregations run over the query's matches, not the returned page."""

    def test_size_zero_still_aggregates_everything(self, client: TestClient) -> None:
        resp = client.post(
            SEARCH_URL,
            json={"size": 0, "aggs": {"c": {"value_count": {"field": "signal.rule.id"}}}},
            headers=ES_AUTH,
        ).json()

        assert resp["hits"]["hits"] == []
        assert resp["aggregations"]["c"]["value"] == resp["hits"]["total"]["value"]

    def test_query_narrows_the_aggregation(self, client: TestClient) -> None:
        resp = client.post(
            SEARCH_URL,
            json={
                "size": 0,
                "query": {"term": {"signal.rule.severity": "low"}},
                "aggs": {"c": {"value_count": {"field": "signal.rule.id"}}},
            },
            headers=ES_AUTH,
        ).json()

        assert resp["aggregations"]["c"]["value"] == resp["hits"]["total"]["value"]


class TestAggregationErrors:
    """An aggregation we cannot run is a 400, not an empty result."""

    def test_unknown_type_is_rejected(self, client: TestClient) -> None:
        resp = client.post(
            SEARCH_URL,
            json={"aggs": {"x": {"definitely_not_an_agg": {}}}},
            headers=ES_AUTH,
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["type"] == "parsing_exception"


class TestTrackTotalHits:
    """``track_total_hits: false`` omits the total."""

    def test_false_omits_total(self, client: TestClient) -> None:
        body = client.post(
            SEARCH_URL, json={"size": 1, "track_total_hits": False}, headers=ES_AUTH,
        ).json()
        assert "total" not in body["hits"]

    def test_default_reports_total(self, client: TestClient) -> None:
        body = client.post(SEARCH_URL, json={"size": 1}, headers=ES_AUTH).json()
        assert body["hits"]["total"]["value"] > 0


class TestClusterApis:
    """The calls a client makes before it trusts a cluster."""

    def test_cluster_health(self, client: TestClient) -> None:
        body = client.get("/elastic/_cluster/health", headers=ES_AUTH).json()
        assert body["status"] in ("green", "yellow", "red")
        assert "number_of_nodes" in body

    def test_cat_indices_lists_backed_indices(self, client: TestClient) -> None:
        rows = client.get("/elastic/_cat/indices", headers=ES_AUTH).json()
        assert rows
        assert {"index", "health", "docs.count"} <= set(rows[0])

    def test_cat_health(self, client: TestClient) -> None:
        rows = client.get("/elastic/_cat/health", headers=ES_AUTH).json()
        assert len(rows) == 1

    def test_authenticate_reports_the_user(self, client: TestClient) -> None:
        body = client.get("/elastic/_security/_authenticate", headers=ES_AUTH).json()
        assert body["username"]
        assert body["enabled"] is True


class TestCountAndMget:
    """``_count`` and ``_mget``."""

    def test_count_matches_search_total(self, client: TestClient) -> None:
        counted = client.post(
            f"/elastic/{INDEX}/_count", json={}, headers=ES_AUTH,
        ).json()["count"]
        searched = client.post(
            SEARCH_URL, json={"size": 0}, headers=ES_AUTH,
        ).json()["hits"]["total"]["value"]

        assert counted == searched

    def test_count_honours_a_query(self, client: TestClient) -> None:
        body = {"query": {"term": {"signal.rule.severity": "low"}}}
        counted = client.post(
            f"/elastic/{INDEX}/_count", json=body, headers=ES_AUTH,
        ).json()["count"]
        searched = client.post(
            SEARCH_URL, json={"size": 0, **body}, headers=ES_AUTH,
        ).json()["hits"]["total"]["value"]

        assert counted == searched

    def test_count_on_a_missing_index_is_404(self, client: TestClient) -> None:
        resp = client.post("/elastic/no_such_index/_count", json={}, headers=ES_AUTH)
        assert resp.status_code == 404

    def test_mget_reports_misses(self, client: TestClient) -> None:
        body = client.post(
            f"/elastic/{INDEX}/_mget", json={"ids": ["not-a-real-id"]}, headers=ES_AUTH,
        ).json()
        assert body["docs"][0]["found"] is False

    def test_mget_finds_a_real_document(self, client: TestClient) -> None:
        hit = client.post(SEARCH_URL, json={"size": 1}, headers=ES_AUTH).json()
        doc_id = hit["hits"]["hits"][0]["_id"]

        body = client.post(
            f"/elastic/{INDEX}/_mget", json={"ids": [doc_id]}, headers=ES_AUTH,
        ).json()

        assert body["docs"][0]["found"] is True


class TestGetSearchIsServed:
    """Elasticsearch accepts GET with a body on ``_search``."""

    def test_get_search_with_body(self, client: TestClient) -> None:
        resp = client.request(
            "GET", SEARCH_URL, json={"size": 1}, headers=ES_AUTH,
        )
        assert resp.status_code == 200
        assert len(resp.json()["hits"]["hits"]) == 1


class TestDocumentWritesPersist:
    """``POST _doc`` used to acknowledge a write it never performed."""

    URL = f"/elastic/{INDEX}/_doc/round-trip-probe"

    def test_write_then_read(self, client: TestClient) -> None:
        created = client.post(self.URL, json={"hostname": "ZZZ"}, headers=ES_AUTH)
        assert created.json()["result"] == "created"

        fetched = client.get(self.URL, headers=ES_AUTH)
        assert fetched.status_code == 200
        assert fetched.json()["found"] is True
        assert fetched.json()["_source"] == {"hostname": "ZZZ"}

    def test_rewrite_increments_version(self, client: TestClient) -> None:
        client.post(self.URL, json={"n": 1}, headers=ES_AUTH)
        second = client.post(self.URL, json={"n": 2}, headers=ES_AUTH)

        assert second.json()["result"] == "updated"
        assert second.json()["_version"] == 2

    def test_put_is_served(self, client: TestClient) -> None:
        # PUT is the primary index API in real ES; only POST was routed.
        resp = client.put(self.URL, json={"n": 1}, headers=ES_AUTH)
        assert resp.status_code == 200

    def test_delete_removes_the_document(self, client: TestClient) -> None:
        client.post(self.URL, json={"n": 1}, headers=ES_AUTH)
        deleted = client.delete(self.URL, headers=ES_AUTH)
        assert deleted.json()["result"] == "deleted"

        assert client.get(self.URL, headers=ES_AUTH).status_code == 404

    def test_delete_of_a_missing_document_is_404(self, client: TestClient) -> None:
        resp = client.delete(f"/elastic/{INDEX}/_doc/never-written", headers=ES_AUTH)
        assert resp.status_code == 404


class TestMatchIsAnalyzed:
    """``match`` compares analysed tokens, not raw substrings."""

    def _search(self, client: TestClient, query: dict) -> list:
        return list(client.post(
            SEARCH_URL, json={"query": query, "size": 100}, headers=ES_AUTH,
        ).json()["hits"]["hits"])

    def test_partial_token_does_not_match(self, client: TestClient) -> None:
        # "SERV" is not a token any analyzer produces from "SERVER-KQEZSV".
        assert self._search(client, {"match": {"host.name": "SERV"}}) == []

    def test_whole_token_matches(self, client: TestClient) -> None:
        sample = client.post(
            SEARCH_URL, json={"size": 1}, headers=ES_AUTH,
        ).json()["hits"]["hits"][0]["_source"]["host"]["name"]
        token = sample.split("-")[0]

        assert self._search(client, {"match": {"host.name": token}})

    def test_match_phrase_needs_contiguous_tokens(self, client: TestClient) -> None:
        assert self._search(
            client, {"match_phrase": {"host.name": "kqezsv server"}},
        ) == []


class TestScoreSorting:
    """``_score`` and ``_doc`` are metadata, not ``_source`` fields."""

    def test_sort_by_score_is_accepted(self, client: TestClient) -> None:
        resp = client.post(
            SEARCH_URL, json={"size": 3, "sort": ["_score"]}, headers=ES_AUTH,
        )
        assert resp.status_code == 200
        assert len(resp.json()["hits"]["hits"]) == 3

    def test_sort_by_score_does_not_scramble_results(self, client: TestClient) -> None:
        # Every document scores the same here, so the order must be preserved
        # rather than bucketed by a field lookup that finds nothing.
        plain = client.post(
            SEARCH_URL, json={"size": 5}, headers=ES_AUTH,
        ).json()["hits"]["hits"]
        scored = client.post(
            SEARCH_URL, json={"size": 5, "sort": ["_score"]}, headers=ES_AUTH,
        ).json()["hits"]["hits"]

        assert [h["_id"] for h in plain] == [h["_id"] for h in scored]
