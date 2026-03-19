"""Integration tests for Elasticsearch REST API endpoints.

Verifies cluster info, search with query DSL, pagination, mapping, stats,
and document retrieval at ``/elastic``.
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}


class TestClusterInfo:
    """Tests for GET /elastic/ — cluster info endpoint."""

    def test_cluster_info_returns_200(self, client: TestClient) -> None:
        """Cluster info endpoint should return 200 with valid auth."""
        resp = client.get("/elastic/", headers=ES_AUTH)
        assert resp.status_code == 200

    def test_cluster_info_has_correct_structure(self, client: TestClient) -> None:
        """Cluster info must include name, cluster_name, version, and tagline."""
        body = client.get("/elastic/", headers=ES_AUTH).json()
        assert body["name"] == "mock-es-node-01"
        assert body["cluster_name"] == "mockdr-elastic"
        assert "version" in body
        assert body["version"]["number"] == "8.12.0"
        assert body["tagline"] == "You Know, for Search"

    def test_cluster_info_version_fields(self, client: TestClient) -> None:
        """Version object must contain build_flavor, lucene_version, etc."""
        version = client.get("/elastic/", headers=ES_AUTH).json()["version"]
        expected_fields = [
            "number", "build_flavor", "build_type", "build_hash",
            "build_date", "lucene_version",
            "minimum_wire_compatibility_version",
            "minimum_index_compatibility_version",
        ]
        for field in expected_fields:
            assert field in version, f"Missing version field: {field}"


class TestEsSearch:
    """Tests for POST /elastic/{index}/_search."""

    def test_search_alerts_match_all(self, client: TestClient) -> None:
        """Searching .siem-signals-default with match_all should return alerts."""
        resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={"query": {"match_all": {}}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "hits" in body
        assert "total" in body["hits"]
        # 45 seeded alerts
        assert body["hits"]["total"]["value"] == 45
        assert body["hits"]["total"]["relation"] == "eq"

    def test_search_endpoints_match_all(self, client: TestClient) -> None:
        """Searching metrics-endpoint.metadata_current_default should return endpoints."""
        resp = client.post(
            "/elastic/metrics-endpoint.metadata_current_default/_search",
            headers=ES_AUTH,
            json={"query": {"match_all": {}}},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["hits"]["total"]["value"] > 0

    def test_search_response_envelope(self, client: TestClient) -> None:
        """Search response must have took, timed_out, _shards, and hits."""
        resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={},
        )
        body = resp.json()
        assert "took" in body
        assert body["timed_out"] is False
        assert "_shards" in body
        shards = body["_shards"]
        assert shards["failed"] == 0
        assert "hits" in body

    def test_search_with_bool_must_match(self, client: TestClient) -> None:
        """Boolean query with must/match should filter results."""
        resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={
                "query": {
                    "bool": {
                        "must": [
                            {"match": {"signal_status": "open"}},
                        ],
                    },
                },
            },
        )
        assert resp.status_code == 200
        hits = resp.json()["hits"]["hits"]
        # All returned hits should have signal_status == "open"
        for hit in hits:
            assert hit["_source"]["signal_status"] == "open"

    def test_search_with_term_query(self, client: TestClient) -> None:
        """Term query should perform exact match filtering."""
        resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={
                "query": {
                    "term": {"signal_status": "closed"},
                },
            },
        )
        assert resp.status_code == 200
        for hit in resp.json()["hits"]["hits"]:
            assert hit["_source"]["signal_status"] == "closed"

    def test_search_with_size_param(self, client: TestClient) -> None:
        """The 'size' parameter should limit the number of returned hits."""
        resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={"size": 3},
        )
        assert resp.status_code == 200
        hits = resp.json()["hits"]["hits"]
        assert len(hits) <= 3

    def test_search_with_from_and_size_pagination(self, client: TestClient) -> None:
        """'from' and 'size' should produce paginated, non-overlapping pages."""
        page1 = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={"from": 0, "size": 5},
        ).json()["hits"]["hits"]

        page2 = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={"from": 5, "size": 5},
        ).json()["hits"]["hits"]

        ids1 = {h["_id"] for h in page1}
        ids2 = {h["_id"] for h in page2}
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"

    def test_search_unknown_index_returns_empty(self, client: TestClient) -> None:
        """Searching a non-existent index should return zero hits."""
        resp = client.post(
            "/elastic/totally-unknown-index/_search",
            headers=ES_AUTH,
            json={"query": {"match_all": {}}},
        )
        assert resp.status_code == 200
        assert resp.json()["hits"]["total"]["value"] == 0
        assert resp.json()["hits"]["hits"] == []

    def test_search_hits_have_source_and_meta(self, client: TestClient) -> None:
        """Each hit must include _index, _id, _score, and _source."""
        resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={"size": 1},
        )
        hit = resp.json()["hits"]["hits"][0]
        assert "_index" in hit
        assert "_id" in hit
        assert "_source" in hit
        assert isinstance(hit["_source"], dict)


class TestEsMapping:
    """Tests for GET /elastic/{index}/_mapping."""

    def test_get_alerts_mapping(self, client: TestClient) -> None:
        """Mapping for .siem-signals-default should include expected fields."""
        resp = client.get(
            "/elastic/.siem-signals-default/_mapping",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        body = resp.json()
        props = body[".siem-signals-default"]["mappings"]["properties"]
        assert "@timestamp" in props
        assert "signal.rule.id" in props
        assert "signal.status" in props

    def test_get_endpoint_mapping(self, client: TestClient) -> None:
        """Mapping for metrics-endpoint index should include host/agent fields."""
        resp = client.get(
            "/elastic/metrics-endpoint.metadata_current_default/_mapping",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        body = resp.json()
        props = body["metrics-endpoint.metadata_current_default"]["mappings"]["properties"]
        assert "agent.id" in props
        assert "host.hostname" in props

    def test_unknown_index_mapping_returns_empty_properties(self, client: TestClient) -> None:
        """Unknown index should return an empty properties map."""
        resp = client.get(
            "/elastic/unknown-index/_mapping",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["unknown-index"]["mappings"]["properties"] == {}


class TestEsStats:
    """Tests for GET /elastic/{index}/_stats."""

    def test_get_alerts_stats(self, client: TestClient) -> None:
        """Stats for .siem-signals-default should reflect seeded alert count."""
        resp = client.get(
            "/elastic/.siem-signals-default/_stats",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "_shards" in body
        # 45 seeded alerts
        doc_count = body["_all"]["primaries"]["docs"]["count"]
        assert doc_count == 45

    def test_stats_response_structure(self, client: TestClient) -> None:
        """Stats response must have _shards, _all, and indices sections."""
        body = client.get(
            "/elastic/.siem-signals-default/_stats",
            headers=ES_AUTH,
        ).json()
        assert "_shards" in body
        assert "_all" in body
        assert "indices" in body
        assert ".siem-signals-default" in body["indices"]


class TestEsGetDoc:
    """Tests for GET /elastic/{index}/_doc/{doc_id}."""

    def test_get_existing_document(self, client: TestClient) -> None:
        """Getting a document by ID that exists should return found=True.

        The ``es_get_doc`` handler matches against the ``id`` field inside
        each record (the domain entity key), not the random Elasticsearch
        ``_id`` generated by ``wrap_as_hits``.
        """
        # First get an alert's domain ID via search _source
        search_resp = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={"size": 1},
        )
        entity_id = search_resp.json()["hits"]["hits"][0]["_source"]["id"]

        resp = client.get(
            f"/elastic/.siem-signals-default/_doc/{entity_id}",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["found"] is True
        assert body["_id"] == entity_id
        assert body["_index"] == ".siem-signals-default"
        assert "_source" in body

    def test_get_nonexistent_document(self, client: TestClient) -> None:
        """Getting a non-existent document should return found=False."""
        resp = client.get(
            "/elastic/.siem-signals-default/_doc/does-not-exist",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["found"] is False
        assert body["_id"] == "does-not-exist"
