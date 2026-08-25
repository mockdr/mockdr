"""``PUT /{index}`` with mappings, and what the index reports afterwards.

Measured against Elasticsearch 8.15: the mappings a client sends come back
from ``GET /{index}`` and ``GET /{index}/_mapping``, a document adds the
fields it introduces, ``PUT /{index}/_mapping`` takes new fields and refuses
a type change, and ``_field_caps`` answers what each field is — the endpoint
every Kibana data view asks for, which mockdr did not serve at all.
"""
import base64

import pytest
from fastapi.testclient import TestClient

from main import app

AUTH = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
INDEX = "mapping-test"
MAPPING = {"mappings": {"properties": {
    "host": {"type": "keyword"},
    "msg": {"type": "text"},
    "sev": {"type": "integer"},
}}}


@pytest.fixture
def client() -> TestClient:
    """A client with the test index created and one document in it."""
    with TestClient(app) as test_client:
        test_client.delete(f"/elastic/{INDEX}", headers=AUTH)
        test_client.put(f"/elastic/{INDEX}", headers=AUTH, json=MAPPING)
        test_client.put(
            f"/elastic/{INDEX}/_doc/1", headers=AUTH,
            json={"host": "srv-1", "msg": "a b", "sev": 1, "extra": "dynamic"},
        )
        yield test_client
        test_client.delete(f"/elastic/{INDEX}", headers=AUTH)


class TestTheMappingComesBack:
    """What a client is told about the index it created."""

    def test_the_declared_fields_are_kept(self, client: TestClient) -> None:
        body = client.get(f"/elastic/{INDEX}/_mapping", headers=AUTH).json()
        properties = body[INDEX]["mappings"]["properties"]
        assert properties["host"] == {"type": "keyword"}
        assert properties["msg"] == {"type": "text"}

    def test_a_written_document_adds_its_own(self, client: TestClient) -> None:
        body = client.get(f"/elastic/{INDEX}/_mapping", headers=AUTH).json()
        extra = body[INDEX]["mappings"]["properties"]["extra"]
        assert extra["type"] == "text"
        assert extra["fields"]["keyword"]["ignore_above"] == 256

    def test_get_index_reports_them_too(self, client: TestClient) -> None:
        body = client.get(f"/elastic/{INDEX}", headers=AUTH).json()
        assert body[INDEX]["mappings"]["properties"]["host"] == {"type": "keyword"}

    def test_one_field_can_be_asked_for(self, client: TestClient) -> None:
        body = client.get(f"/elastic/{INDEX}/_mapping/field/host", headers=AUTH).json()
        assert body[INDEX]["mappings"]["host"] == {
            "full_name": "host", "mapping": {"host": {"type": "keyword"}},
        }

    def test_a_field_the_index_lacks_reports_nothing(self, client: TestClient) -> None:
        body = client.get(f"/elastic/{INDEX}/_mapping/field/nope", headers=AUTH).json()
        assert body[INDEX]["mappings"] == {}


class TestPutMapping:
    """Adding fields after the fact."""

    def test_a_new_field_is_acknowledged(self, client: TestClient) -> None:
        response = client.put(
            f"/elastic/{INDEX}/_mapping", headers=AUTH,
            json={"properties": {"added": {"type": "keyword"}}},
        )
        assert response.status_code == 200
        assert response.json() == {"acknowledged": True}
        body = client.get(f"/elastic/{INDEX}/_mapping", headers=AUTH).json()
        assert body[INDEX]["mappings"]["properties"]["added"] == {"type": "keyword"}

    def test_changing_a_type_is_refused(self, client: TestClient) -> None:
        response = client.put(
            f"/elastic/{INDEX}/_mapping", headers=AUTH,
            json={"properties": {"sev": {"type": "keyword"}}},
        )
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["type"] == "illegal_argument_exception"
        assert error["reason"] == (
            "mapper [sev] cannot be changed from type [integer] to [keyword]"
        )

    def test_an_index_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        response = client.put(
            "/elastic/no-such-index/_mapping", headers=AUTH,
            json={"properties": {"a": {"type": "keyword"}}},
        )
        assert response.status_code == 404


class TestFieldCaps:
    """What every Kibana data view asks for."""

    def test_each_field_reports_its_type(self, client: TestClient) -> None:
        body = client.get(
            f"/elastic/{INDEX}/_field_caps", headers=AUTH, params={"fields": "host,msg"},
        ).json()
        assert body["indices"] == [INDEX]
        assert body["fields"]["host"]["keyword"]["aggregatable"] is True
        assert body["fields"]["msg"]["text"]["aggregatable"] is False

    def test_the_fields_can_be_asked_for_in_the_body(self, client: TestClient) -> None:
        body = client.post(
            f"/elastic/{INDEX}/_field_caps", headers=AUTH, json={"fields": ["host"]},
        ).json()
        assert "host" in body["fields"]

    def test_an_index_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        response = client.get(
            "/elastic/no-such-index/_field_caps", headers=AUTH, params={"fields": "*"},
        )
        assert response.status_code == 404


class TestFielddata:
    """A text field cannot be aggregated, and a cluster says so."""

    def test_a_terms_aggregation_over_text_is_refused(self, client: TestClient) -> None:
        response = client.post(
            f"/elastic/{INDEX}/_search", headers=AUTH,
            json={"size": 0, "aggs": {"a": {"terms": {"field": "msg"}}}},
        )
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["type"] == "search_phase_execution_exception"
        assert error["root_cause"][0]["reason"].startswith(
            f"Fielddata is disabled on [msg] in [{INDEX}].",
        )

    def test_the_keyword_subfield_aggregates(self, client: TestClient) -> None:
        response = client.post(
            f"/elastic/{INDEX}/_search", headers=AUTH,
            json={"size": 0, "aggs": {"a": {"terms": {"field": "extra.keyword"}}}},
        )
        assert response.status_code == 200

    def test_a_keyword_field_aggregates(self, client: TestClient) -> None:
        response = client.post(
            f"/elastic/{INDEX}/_search", headers=AUTH,
            json={"size": 0, "aggs": {"a": {"terms": {"field": "host"}}}},
        )
        assert response.status_code == 200
        buckets = response.json()["aggregations"]["a"]["buckets"]
        assert [b["key"] for b in buckets] == ["srv-1"]
