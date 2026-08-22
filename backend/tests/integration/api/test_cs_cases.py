"""Integration tests for CrowdStrike Cases endpoints.

Verifies case queries, entity retrieval, creation, updates, tag management,
response envelope structure, and authentication enforcement.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first_case_id(client: TestClient, headers: dict[str, str]) -> str:
    """Return the first case ID from the query endpoint."""
    resp = client.get(
        "/cs/cases/queries/cases/v1",
        headers=headers,
        params={"limit": 1},
    )
    return resp.json()["resources"][0]


# ---------------------------------------------------------------------------
# Query case IDs
# ---------------------------------------------------------------------------

class TestQueryCaseIds:
    """Tests for GET /cs/cases/queries/cases/v1."""

    def test_query_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/cases/queries/cases/v1", headers=headers)
        assert resp.status_code == 200

    def test_query_returns_8_cases(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/cases/queries/cases/v1",
            headers=headers,
            params={"limit": 100},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 8

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/cases/queries/cases/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "query_time" in meta
        assert "pagination" in meta
        assert body["errors"] == []
        assert "resources" in body

    def test_resources_are_id_strings(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/cases/queries/cases/v1",
            headers=headers,
            params={"limit": 5},
        )
        for rid in resp.json()["resources"]:
            assert isinstance(rid, str)
            assert len(rid) > 0

    def test_pagination_offset_returns_disjoint_pages(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/cases/queries/cases/v1",
            headers=headers,
            params={"offset": 0, "limit": 4},
        )
        r2 = client.get(
            "/cs/cases/queries/cases/v1",
            headers=headers,
            params={"offset": 4, "limit": 4},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2)

    def test_pagination_limit_respected(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/cases/queries/cases/v1",
            headers=headers,
            params={"limit": 3},
        )
        assert len(resp.json()["resources"]) == 3

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.get("/cs/cases/queries/cases/v1")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Get case entities
# ---------------------------------------------------------------------------

class TestGetCaseEntities:
    """Tests for POST /cs/alerts/entities/cases/GET/v1."""









class TestCreateCase:
    """Tests for POST /cs/alerts/entities/cases/v1."""







class TestUpdateCase:
    """Tests for PATCH /cs/alerts/entities/cases/v1."""





class TestCaseTags:
    """Tests for POST and DELETE /cs/cases/entities/case-tags/v1."""

    def test_add_tags_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/cases/entities/case-tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["new-tag"]},
        )
        assert resp.status_code == 200


    def test_add_tags_response_contains_case_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/cases/entities/case-tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["check-resources"]},
        )
        body = resp.json()
        assert body["errors"] == []
        assert len(body["resources"]) == 1
        assert body["resources"][0]["id"] == case_id


    def test_delete_tags_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        # Add a tag first so we have something to delete
        client.post(
            "/cs/cases/entities/case-tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["removable"]},
        )
        resp = client.request(
            "DELETE",
            "/cs/cases/entities/case-tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["removable"]},
        )
        assert resp.status_code == 200


    def test_delete_tags_response_contains_case_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.request(
            "DELETE",
            "/cs/cases/entities/case-tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["nonexistent-tag"]},
        )
        body = resp.json()
        assert body["errors"] == []
        assert body["resources"][0]["id"] == case_id


    def test_add_tags_auth_required(self, client: TestClient) -> None:
        resp = client.post(
            "/cs/cases/entities/case-tags/v1",
            json={"id": "some-id", "tags": ["tag"]},
        )
        assert resp.status_code == 401

    def test_delete_tags_auth_required(self, client: TestClient) -> None:
        resp = client.request(
            "DELETE",
            "/cs/cases/entities/case-tags/v1",
            json={"id": "some-id", "tags": ["tag"]},
        )
        assert resp.status_code == 401
