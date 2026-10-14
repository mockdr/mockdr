"""Integration tests for Elastic Security Detection Engine Signals (Alerts) API.

Verifies signal search, status updates, tag management, and assignee
management at ``/kibana/api/detection_engine/signals``.
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}

KBN_WRITE_HEADERS = {
    **ES_AUTH,
    "kbn-xsrf": "true",
}


def _get_alert_ids(client: TestClient, count: int = 2) -> list[str]:
    """Return a list of seeded alert IDs by searching signals.

    ``_id`` now identifies the document rather than being a fresh UUID per
    response, so it is the id to address the alert by — as it is in a real
    cluster.
    """
    resp = client.post(
        "/kibana/api/detection_engine/signals/search",
        headers={**ES_AUTH, "kbn-xsrf": "true"},
        json={"query": {"match_all": {}}, "size": count},
    )
    return [h["_id"] for h in resp.json()["hits"]["hits"]]


class TestSignalsSearch:
    """Tests for POST /kibana/api/detection_engine/signals/search."""

    def test_search_returns_200(self, client: TestClient) -> None:
        """Signals search should return 200 with valid auth."""
        resp = client.post(
            "/kibana/api/detection_engine/signals/search",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"query": {"match_all": {}}},
        )
        assert resp.status_code == 200

    def test_search_response_has_es_envelope(self, client: TestClient) -> None:
        """Response must use the Elasticsearch hits envelope format."""
        body = client.post(
            "/kibana/api/detection_engine/signals/search",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"query": {"match_all": {}}},
        ).json()
        assert "hits" in body
        assert "total" in body["hits"]
        assert body["hits"]["total"]["relation"] == "eq"
        assert "hits" in body["hits"]

    def test_search_returns_45_seeded_alerts(self, client: TestClient) -> None:
        """Seeder creates 45 alerts; total should reflect that."""
        body = client.post(
            "/kibana/api/detection_engine/signals/search",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"query": {"match_all": {}}, "size": 100},
        ).json()
        assert body["hits"]["total"]["value"] == 45

    def test_search_with_size_limits_hits(self, client: TestClient) -> None:
        """Size parameter should limit the number of returned hits."""
        body = client.post(
            "/kibana/api/detection_engine/signals/search",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"size": 3},
        ).json()
        assert len(body["hits"]["hits"]) <= 3

    def test_search_hit_has_source_fields(self, client: TestClient) -> None:
        """Each hit should have _source with alert-relevant fields."""
        body = client.post(
            "/kibana/api/detection_engine/signals/search",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"size": 1},
        ).json()
        source = body["hits"]["hits"][0]["_source"]
        # Real alert documents are ECS with the rule metadata under
        # `kibana.alert.*` — the alerts-as-data index 8.15 searches here, not
        # the legacy `signal.*` one; the flat snake_case names this used to
        # assert exist in no cluster.
        expected = [
            "@timestamp", "kibana", "agent", "host", "process", "user", "event",
        ]
        for field in expected:
            assert field in source, f"Missing alert field: {field}"
        assert "signal" not in source
        assert source["kibana"]["alert"]["rule"]["name"]
        assert source["host"]["name"]


class TestSignalsSearchIsAPassThrough:
    """signals/search searched the legacy index, dropped `aggs`, always said `eq`.

    Kibana 8.15's route (query_signals_route.ts at v8.15.0) takes `query`,
    `aggs`, `_source`, `fields`, `track_total_hits`, `size`,
    `runtime_mappings` and `sort` from the body, searches the space's
    `.alerts-security.alerts-<space>` with `ignore_unavailable`, and answers
    what Elasticsearch answered. `from` and `search_after` are not passed on.
    The route also requires `kbn-xsrf`, like every Kibana POST that does not
    opt out — it does not.
    """

    URL = "/kibana/api/detection_engine/signals/search"

    def test_aggregations_come_back(self, client: TestClient) -> None:
        body = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "size": 0, "aggs": {"sev": {"terms": {"field": "kibana.alert.severity"}}},
        }).json()
        buckets = body["aggregations"]["sev"]["buckets"]
        assert sum(b["doc_count"] for b in buckets) == body["hits"]["total"]["value"]

    def test_the_hits_name_the_alerts_index(self, client: TestClient) -> None:
        hit = client.post(self.URL, headers=KBN_WRITE_HEADERS,
                          json={"size": 1}).json()["hits"]["hits"][0]
        assert hit["_index"].startswith(".alerts-security.alerts-")

    def test_a_query_on_the_kibana_alert_fields(self, client: TestClient) -> None:
        body = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "size": 100, "query": {"term": {"kibana.alert.severity": "critical"}},
        }).json()
        assert body["hits"]["hits"]
        assert {h["_source"]["kibana"]["alert"]["severity"]
                for h in body["hits"]["hits"]} == {"critical"}

    def test_a_terms_query_on_the_category_list(self, client: TestClient) -> None:
        """`event.category` is a list on every alert; `terms` must see into it."""
        body = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "size": 0, "query": {"terms": {"event.category": ["intrusion_detection"]}},
        }).json()
        assert body["hits"]["total"]["value"] == 45

    def test_track_total_hits_caps_the_relation(self, client: TestClient) -> None:
        total = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "size": 0, "track_total_hits": 10,
        }).json()["hits"]["total"]
        assert total == {"value": 10, "relation": "gte"}

    def test_from_is_not_passed_on(self, client: TestClient) -> None:
        first = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "size": 2, "sort": [{"@timestamp": "desc"}]}).json()["hits"]["hits"]
        paged = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "size": 2, "from": 2, "sort": [{"@timestamp": "desc"}]}).json()["hits"]["hits"]
        assert [h["_id"] for h in paged] == [h["_id"] for h in first]

    def test_a_body_of_only_what_it_drops_is_empty(self, client: TestClient) -> None:
        resp = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={"from": 5})
        assert resp.status_code == 400
        assert resp.json()["message"] == '"value" must have at least 1 children'

    def test_without_kbn_xsrf_is_refused(self, client: TestClient) -> None:
        resp = client.post(self.URL, headers=ES_AUTH, json={"size": 1})
        assert resp.status_code == 400
        assert resp.json()["message"] == "Request must contain a kbn-xsrf header."

    def test_without_credentials_the_401_comes_first(self, client: TestClient) -> None:
        """The xsrf check is a post-auth handler in Kibana's lifecycle."""
        resp = client.post(self.URL, json={"size": 1})
        assert resp.status_code == 401

    def test_an_elasticsearch_refusal_is_relayed(self, client: TestClient) -> None:
        resp = client.post(self.URL, headers=KBN_WRITE_HEADERS, json={
            "query": {"no_such_query": {}}})
        assert resp.status_code == 400
        assert resp.json()["message"].startswith("parsing_exception: ")
        assert resp.json()["status_code"] == 400


class TestUpdateSignalStatus:
    """Tests for POST /kibana/api/detection_engine/signals/status."""

    def test_close_alert(self, client: TestClient) -> None:
        """Setting status to 'closed' should update the alert."""
        alert_ids = _get_alert_ids(client, 1)
        resp = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers=KBN_WRITE_HEADERS,
            json={"signal_ids": alert_ids, "status": "closed"},
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] == 1

    def test_acknowledge_alert(self, client: TestClient) -> None:
        """Setting status to 'acknowledged' should succeed."""
        alert_ids = _get_alert_ids(client, 1)
        resp = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers=KBN_WRITE_HEADERS,
            json={"signal_ids": alert_ids, "status": "acknowledged"},
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] == 1

    def test_status_update_persists(self, client: TestClient) -> None:
        """After closing an alert, searching by status should reflect it."""
        alert_ids = _get_alert_ids(client, 1)
        client.post(
            "/kibana/api/detection_engine/signals/status",
            headers=KBN_WRITE_HEADERS,
            json={"signal_ids": alert_ids, "status": "closed"},
        )
        # Verify via Elasticsearch search that the alert is now closed
        body = client.post(
            "/elastic/.siem-signals-default/_search",
            headers=ES_AUTH,
            json={
                "query": {"term": {"signal.rule.id": alert_ids[0]}},
                "size": 1,
            },
        ).json()
        hits = body["hits"]["hits"]
        assert len(hits) == 1
        assert hits[0]["_source"]["signal"]["status"] == "closed"

    def test_missing_signal_ids_returns_400(self, client: TestClient) -> None:
        """Missing signal_ids should return 400."""
        resp = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers=KBN_WRITE_HEADERS,
            json={"status": "closed"},
        )
        assert resp.status_code == 400

    def test_missing_status_returns_400(self, client: TestClient) -> None:
        """Missing status field should return 400."""
        resp = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers=KBN_WRITE_HEADERS,
            json={"signal_ids": ["some-id"]},
        )
        assert resp.status_code == 400

    def test_missing_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header should return 400."""
        alert_ids = _get_alert_ids(client, 1)
        resp = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers=ES_AUTH,
            json={"signal_ids": alert_ids, "status": "closed"},
        )
        assert resp.status_code == 400


class TestUpdateSignalTags:
    """Tests for POST /kibana/api/detection_engine/signals/tags."""

    def test_add_tags(self, client: TestClient) -> None:
        """Adding tags should succeed and return updated count."""
        alert_ids = _get_alert_ids(client, 1)
        resp = client.post(
            "/kibana/api/detection_engine/signals/tags",
            headers=KBN_WRITE_HEADERS,
            json={
                "ids": alert_ids,
                "tags": {"tags_to_add": ["investigation", "priority-high"], "tags_to_remove": []},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] == 1

    def test_remove_tags(self, client: TestClient) -> None:
        """Removing tags should succeed."""
        alert_ids = _get_alert_ids(client, 1)
        # All seeded alerts have ["Elastic", "Endpoint"] tags
        resp = client.post(
            "/kibana/api/detection_engine/signals/tags",
            headers=KBN_WRITE_HEADERS,
            json={
                "ids": alert_ids,
                "tags": {"tags_to_add": [], "tags_to_remove": ["Endpoint"]},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] == 1

    def test_missing_ids_returns_400(self, client: TestClient) -> None:
        """Missing ids should return 400."""
        resp = client.post(
            "/kibana/api/detection_engine/signals/tags",
            headers=KBN_WRITE_HEADERS,
            json={"tags": {"tags_to_add": ["test"]}},
        )
        assert resp.status_code == 400


class TestUpdateSignalAssignees:
    """Tests for POST /kibana/api/detection_engine/signals/assignees."""

    def test_add_assignees(self, client: TestClient) -> None:
        """Adding assignees should succeed and return updated count."""
        alert_ids = _get_alert_ids(client, 1)
        resp = client.post(
            "/kibana/api/detection_engine/signals/assignees",
            headers=KBN_WRITE_HEADERS,
            json={
                "ids": alert_ids,
                # `add`/`remove`, and a user id as a plain string: what 8.15
                # takes, where this used to send the shape mockdr stores.
                "assignees": {"add": ["analyst-001"], "remove": []},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] == 1

    def test_remove_assignees(self, client: TestClient) -> None:
        """Removing assignees should succeed."""
        alert_ids = _get_alert_ids(client, 1)
        # First add, then remove
        client.post(
            "/kibana/api/detection_engine/signals/assignees",
            headers=KBN_WRITE_HEADERS,
            json={
                "ids": alert_ids,
                "assignees": {"add": ["to-remove"], "remove": []},
            },
        )
        resp = client.post(
            "/kibana/api/detection_engine/signals/assignees",
            headers=KBN_WRITE_HEADERS,
            json={
                "ids": alert_ids,
                "assignees": {"add": [], "remove": ["to-remove"]},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["updated"] == 1

    def test_missing_ids_returns_400(self, client: TestClient) -> None:
        """Missing ids should return 400."""
        resp = client.post(
            "/kibana/api/detection_engine/signals/assignees",
            headers=KBN_WRITE_HEADERS,
            json={"assignees": {"assignees_to_add": [{"uid": "user"}]}},
        )
        assert resp.status_code == 400
