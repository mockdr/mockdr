"""Kibana list-envelope conformance.

Three Kibana list APIs that look alike in fact use three different envelopes,
and mockdr previously served one shared shape for all of them. A client
written against the real API read ``undefined`` for the page size, the
collection, or the comment totals depending on which endpoint it called.

Field names below come from Kibana's own generated schemas:
``find_rules_route.gen.ts`` (RuleResponse), ``case/v1.ts``
(CasesFindResponseRt, CaseRt).
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}


class TestRulesFindEnvelope:
    """``perPage`` in the response, ``per_page`` in the request."""

    def test_uses_camel_case_page_size(self, client: TestClient) -> None:
        body = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH, params={"per_page": 5},
        ).json()

        assert body["perPage"] == 5
        assert "per_page" not in body

    def test_collection_is_named_data(self, client: TestClient) -> None:
        body = client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
        ).json()
        assert isinstance(body["data"], list)


class TestCasesFindEnvelope:
    """``cases`` — not ``data`` — plus the per-status counts."""

    def test_collection_is_named_cases(self, client: TestClient) -> None:
        body = client.get("/kibana/api/cases/_find", headers=ES_AUTH).json()

        assert isinstance(body["cases"], list)
        assert "data" not in body

    def test_carries_status_counts(self, client: TestClient) -> None:
        body = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 100},
        ).json()

        counted = (
            body["count_open_cases"]
            + body["count_in_progress_cases"]
            + body["count_closed_cases"]
        )
        assert counted == body["total"]

    def test_page_size_stays_snake_case_here(self, client: TestClient) -> None:
        # Unlike rules/_find — the two APIs genuinely differ.
        body = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 5},
        ).json()
        assert body["per_page"] == 5

    def test_case_totals_are_camel_case(self, client: TestClient) -> None:
        case = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 1},
        ).json()["cases"][0]

        assert "totalComment" in case
        assert "totalAlerts" in case
        assert "total_comment" not in case
        assert "total_alerts" not in case

    def test_single_case_get_uses_the_same_names(self, client: TestClient) -> None:
        case_id = client.get(
            "/kibana/api/cases/_find", headers=ES_AUTH, params={"perPage": 1},
        ).json()["cases"][0]["id"]

        case = client.get(f"/kibana/api/cases/{case_id}", headers=ES_AUTH).json()

        assert "totalComment" in case
        assert "total_comment" not in case


class TestEndpointMetadataEnvelope:
    """The endpoint metadata list returns ``pageSize``."""

    def test_uses_page_size(self, client: TestClient) -> None:
        body = client.get("/kibana/api/endpoint/metadata", headers=ES_AUTH).json()

        assert "pageSize" in body
        assert "per_page" not in body


class TestSignalStatusEnvelope:
    """``signals/status`` proxies Elasticsearch's update_by_query response."""

    def _alert_ids(self, client: TestClient, count: int = 1) -> list[str]:
        hits = client.post(
            "/kibana/api/detection_engine/signals/search",
            headers=ES_AUTH, json={"size": count},
        ).json()["hits"]["hits"]
        return [h["_id"] for h in hits]

    def test_response_carries_the_update_by_query_members(
        self, client: TestClient,
    ) -> None:
        body = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"signal_ids": self._alert_ids(client), "status": "closed"},
        ).json()

        # `{"updated": N}` alone left a client with nothing to check for
        # version conflicts or failures.
        for member in (
            "took", "timed_out", "total", "updated", "deleted", "batches",
            "version_conflicts", "noops", "retries", "failures",
        ):
            assert member in body, f"missing update_by_query member: {member}"

    def test_updated_count_is_still_reported(self, client: TestClient) -> None:
        ids = self._alert_ids(client, 2)
        body = client.post(
            "/kibana/api/detection_engine/signals/status",
            headers={**ES_AUTH, "kbn-xsrf": "true"},
            json={"signal_ids": ids, "status": "acknowledged"},
        ).json()

        assert body["updated"] == len(ids)
        assert body["total"] == len(ids)


class TestExclusionAndActionEdgeCases:
    """Two bodies that used to raise straight through as 500s."""

    def test_exclusion_list_body_is_accepted(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        # S1 accepts a list under `data` for bulk creation; calling .get() on
        # it raised AttributeError out of the handler.
        resp = client.post(
            "/web/api/v2.1/exclusions",
            json={"data": [{"value": "/tmp/probe", "type": "path", "osType": "linux"}]},
            headers=auth_headers,
        )
        assert resp.status_code == 200

    def test_exclusion_junk_body_is_a_400_not_a_500(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.post(
            "/web/api/v2.1/exclusions",
            json={"data": "not-an-object"},
            headers=auth_headers,
        )
        assert resp.status_code == 400
