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
        "/cs/alerts/queries/cases/v1",
        headers=headers,
        params={"limit": 1},
    )
    return resp.json()["resources"][0]


# ---------------------------------------------------------------------------
# Query case IDs
# ---------------------------------------------------------------------------

class TestQueryCaseIds:
    """Tests for GET /cs/alerts/queries/cases/v1."""

    def test_query_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/alerts/queries/cases/v1", headers=headers)
        assert resp.status_code == 200

    def test_query_returns_8_cases(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"limit": 100},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 8

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/alerts/queries/cases/v1", headers=headers)
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
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"limit": 5},
        )
        for rid in resp.json()["resources"]:
            assert isinstance(rid, str)
            assert len(rid) > 0

    def test_pagination_offset_returns_disjoint_pages(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"offset": 0, "limit": 4},
        )
        r2 = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"offset": 4, "limit": 4},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2)

    def test_pagination_limit_respected(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"limit": 3},
        )
        assert len(resp.json()["resources"]) == 3

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.get("/cs/alerts/queries/cases/v1")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Get case entities
# ---------------------------------------------------------------------------

class TestGetCaseEntities:
    """Tests for POST /cs/alerts/entities/cases/GET/v1."""

    def test_get_case_by_id_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        assert resp.status_code == 200

    def test_get_case_returns_correct_entity(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert resources[0]["id"] == case_id

    def test_case_entity_has_required_fields(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        case = resp.json()["resources"][0]
        required_fields = [
            "id", "cid", "title", "body", "detections",
            "type", "status", "tags", "fine_score",
            "created_time", "last_modified_time",
        ]
        for field in required_fields:
            assert field in case, f"Required field '{field}' missing from case entity"

    def test_get_multiple_cases_by_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"limit": 3},
        )
        ids = query_resp.json()["resources"]
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": ids},
        )
        assert len(resp.json()["resources"]) == 3

    def test_nonexistent_id_returns_empty_resources(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": ["00000000-0000-0000-0000-000000000000"]},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []

    def test_entity_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            json={"ids": []},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Create case
# ---------------------------------------------------------------------------

class TestCreateCase:
    """Tests for POST /cs/alerts/entities/cases/v1."""

    def test_create_case_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"title": "Test Case", "body": "Created in test."},
        )
        assert resp.status_code == 200

    def test_create_case_returns_new_case_with_correct_fields(
        self, client: TestClient
    ) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"title": "New Case Alpha", "body": "Details here."},
        )
        body = resp.json()
        assert body["errors"] == []
        resources = body["resources"]
        assert len(resources) == 1
        case = resources[0]
        assert case["title"] == "New Case Alpha"
        assert case["body"] == "Details here."
        assert case["status"] == "open"
        assert isinstance(case["id"], str)
        assert len(case["id"]) > 0

    def test_create_case_increments_total_count(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        before = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"limit": 100},
        ).json()["meta"]["pagination"]["total"]

        client.post(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"title": "Extra Case", "body": ""},
        )

        after = client.get(
            "/cs/alerts/queries/cases/v1",
            headers=headers,
            params={"limit": 100},
        ).json()["meta"]["pagination"]["total"]

        assert after == before + 1

    def test_create_case_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"title": "Envelope Test", "body": ""},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.post(
            "/cs/alerts/entities/cases/v1",
            json={"title": "Unauthorized", "body": ""},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Update case
# ---------------------------------------------------------------------------

class TestUpdateCase:
    """Tests for PATCH /cs/alerts/entities/cases/v1."""

    def test_update_case_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.patch(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"id": case_id, "status": "closed"},
        )
        assert resp.status_code == 200

    def test_update_case_status_change_persists(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        client.patch(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"id": case_id, "status": "closed"},
        )
        entity_resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        updated = entity_resp.json()["resources"][0]
        assert updated["status"] == "closed"

    def test_update_case_title_change_persists(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        client.patch(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"id": case_id, "title": "Updated Title"},
        )
        entity_resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        assert entity_resp.json()["resources"][0]["title"] == "Updated Title"

    def test_update_case_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.patch(
            "/cs/alerts/entities/cases/v1",
            headers=headers,
            json={"id": case_id, "status": "reopened"},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.patch(
            "/cs/alerts/entities/cases/v1",
            json={"id": "some-id", "status": "closed"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tag management
# ---------------------------------------------------------------------------

class TestCaseTags:
    """Tests for POST and DELETE /cs/alerts/entities/cases/tags/v1."""

    def test_add_tags_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["new-tag"]},
        )
        assert resp.status_code == 200

    def test_add_tags_appends_to_existing_tags(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["integration-test-tag"]},
        )
        entity_resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        tags = entity_resp.json()["resources"][0]["tags"]
        assert "integration-test-tag" in tags

    def test_add_tags_response_contains_case_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["check-resources"]},
        )
        body = resp.json()
        assert body["errors"] == []
        assert len(body["resources"]) == 1
        assert body["resources"][0]["id"] == case_id

    def test_add_tags_no_duplicates(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        # Add the same tag twice
        client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["dedup-tag"]},
        )
        client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["dedup-tag"]},
        )
        entity_resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        tags = entity_resp.json()["resources"][0]["tags"]
        assert tags.count("dedup-tag") == 1

    def test_delete_tags_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        # Add a tag first so we have something to delete
        client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["removable"]},
        )
        resp = client.request(
            "DELETE",
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["removable"]},
        )
        assert resp.status_code == 200

    def test_delete_tags_removes_tag_from_case(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["to-remove"]},
        )
        client.request(
            "DELETE",
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["to-remove"]},
        )
        entity_resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        tags = entity_resp.json()["resources"][0]["tags"]
        assert "to-remove" not in tags

    def test_delete_tags_response_contains_case_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        resp = client.request(
            "DELETE",
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["nonexistent-tag"]},
        )
        body = resp.json()
        assert body["errors"] == []
        assert body["resources"][0]["id"] == case_id

    def test_delete_tags_only_removes_specified_tags(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        case_id = _first_case_id(client, headers)
        client.post(
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["keep-tag", "remove-tag"]},
        )
        client.request(
            "DELETE",
            "/cs/alerts/entities/cases/tags/v1",
            headers=headers,
            json={"id": case_id, "tags": ["remove-tag"]},
        )
        entity_resp = client.post(
            "/cs/alerts/entities/cases/GET/v1",
            headers=headers,
            json={"ids": [case_id]},
        )
        tags = entity_resp.json()["resources"][0]["tags"]
        assert "keep-tag" in tags
        assert "remove-tag" not in tags

    def test_add_tags_auth_required(self, client: TestClient) -> None:
        resp = client.post(
            "/cs/alerts/entities/cases/tags/v1",
            json={"id": "some-id", "tags": ["tag"]},
        )
        assert resp.status_code == 401

    def test_delete_tags_auth_required(self, client: TestClient) -> None:
        resp = client.request(
            "DELETE",
            "/cs/alerts/entities/cases/tags/v1",
            json={"id": "some-id", "tags": ["tag"]},
        )
        assert resp.status_code == 401
