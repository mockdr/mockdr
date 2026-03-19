"""Integration tests for CrowdStrike User Management endpoints.

Verifies user UUID queries, entity retrieval (POST and GET variants),
FQL filtering, pagination, response envelope structure, and auth enforcement.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestQueryUserIds:
    """Tests for GET /cs/user-management/queries/users/v1."""

    def test_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/user-management/queries/users/v1", headers=headers)
        assert resp.status_code == 200

    def test_returns_8_users(self, client: TestClient) -> None:
        """Seed creates exactly 8 CS users; total must reflect that."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"limit": 100},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 8
        assert len(body["resources"]) == 8

    def test_response_envelope_structure(self, client: TestClient) -> None:
        """Response must contain meta.powered_by, meta.trace_id, resources, errors."""
        headers = _cs_auth(client)
        resp = client.get("/cs/user-management/queries/users/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "query_time" in meta
        assert "resources" in body
        assert "errors" in body
        assert body["errors"] == []

    def test_response_includes_pagination_metadata(self, client: TestClient) -> None:
        """Pagination block must include offset, limit, and total."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"limit": 5, "offset": 0},
        )
        pagination = resp.json()["meta"]["pagination"]
        assert pagination["offset"] == 0
        assert pagination["limit"] == 5
        assert pagination["total"] == 8

    def test_resources_are_string_uuids(self, client: TestClient) -> None:
        """Each resource in the query response must be a non-empty string UUID."""
        headers = _cs_auth(client)
        resp = client.get("/cs/user-management/queries/users/v1", headers=headers)
        for resource in resp.json()["resources"]:
            assert isinstance(resource, str)
            assert len(resource) > 0

    def test_pagination_limit_reduces_page_size(self, client: TestClient) -> None:
        """Requesting limit=3 returns exactly 3 IDs, total remains 8."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"limit": 3, "offset": 0},
        )
        body = resp.json()
        assert len(body["resources"]) == 3
        assert body["meta"]["pagination"]["total"] == 8

    def test_pagination_offset_returns_disjoint_pages(self, client: TestClient) -> None:
        """Consecutive pages with offset must not share UUIDs."""
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"offset": 0, "limit": 4},
        )
        r2 = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"offset": 4, "limit": 4},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2), "Paginated pages must not overlap"

    def test_fql_filter_by_uid_email(self, client: TestClient) -> None:
        """FQL filter on uid (email) narrows results to matching users."""
        headers = _cs_auth(client)
        # First fetch all users to grab a known email
        all_ids = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"limit": 100},
        ).json()["resources"]
        entity_resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": all_ids[:1]},
        )
        uid = entity_resp.json()["resources"][0]["uid"]

        filtered = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"filter": f"uid:'{uid}'"},
        )
        assert filtered.status_code == 200
        assert filtered.json()["meta"]["pagination"]["total"] >= 1

    def test_requires_auth(self, client: TestClient) -> None:
        """Unauthenticated request must be rejected with 401."""
        resp = client.get("/cs/user-management/queries/users/v1")
        assert resp.status_code == 401


class TestGetUserEntitiesPost:
    """Tests for POST /cs/user-management/entities/users/GET/v1."""

    def _get_all_user_ids(self, client: TestClient, headers: dict) -> list[str]:
        resp = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"limit": 100},
        )
        return resp.json()["resources"]

    def test_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ids[:1]},
        )
        assert resp.status_code == 200

    def test_response_envelope_structure(self, client: TestClient) -> None:
        """Entity response must contain meta.powered_by, meta.trace_id, resources, errors."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ids[:1]},
        )
        body = resp.json()
        meta = body["meta"]
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "resources" in body
        assert "errors" in body
        assert body["errors"] == []

    def test_returns_correct_user_count(self, client: TestClient) -> None:
        """Requesting 3 IDs returns exactly 3 user entities."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ids[:3]},
        )
        assert len(resp.json()["resources"]) == 3

    def test_user_entity_has_required_fields(self, client: TestClient) -> None:
        """User entity must include uuid, uid, first_name, last_name, and roles."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ids[:1]},
        )
        user = resp.json()["resources"][0]
        required_fields = ["uuid", "uid", "first_name", "last_name", "roles",
                           "cid", "customer", "status", "created_at", "last_login_at"]
        for f in required_fields:
            assert f in user, f"Required field '{f}' missing from user entity"

    def test_user_entity_uuid_matches_requested_id(self, client: TestClient) -> None:
        """The uuid in the returned entity must match what was requested."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        target_id = ids[0]
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": [target_id]},
        )
        assert resp.json()["resources"][0]["uuid"] == target_id

    def test_user_roles_is_a_list(self, client: TestClient) -> None:
        """roles field must be a non-empty list of strings."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ids},
        )
        for user in resp.json()["resources"]:
            assert isinstance(user["roles"], list)
            assert len(user["roles"]) > 0

    def test_uid_is_acmecorp_email(self, client: TestClient) -> None:
        """uid (email) must use the acmecorp.internal seed domain."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ids},
        )
        for user in resp.json()["resources"]:
            assert user["uid"].endswith("@acmecorp.internal"), (
                f"Expected acmecorp.internal email, got: {user['uid']}"
            )

    def test_nonexistent_id_returns_empty_resources(self, client: TestClient) -> None:
        """Unknown UUID must return 200 with empty resources list."""
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": ["00000000-dead-beef-0000-000000000000"]},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []

    def test_requires_auth(self, client: TestClient) -> None:
        """Unauthenticated POST must be rejected with 401."""
        resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            json={"ids": ["some-id"]},
        )
        assert resp.status_code == 401


class TestGetUserEntitiesGet:
    """Tests for GET /cs/user-management/entities/users/v1?ids=..."""

    def _get_all_user_ids(self, client: TestClient, headers: dict) -> list[str]:
        resp = client.get(
            "/cs/user-management/queries/users/v1",
            headers=headers,
            params={"limit": 100},
        )
        return resp.json()["resources"]

    def test_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.get(
            "/cs/user-management/entities/users/v1",
            headers=headers,
            params={"ids": ids[0]},
        )
        assert resp.status_code == 200

    def test_comma_separated_ids_return_multiple_entities(self, client: TestClient) -> None:
        """Comma-separated IDs in a single query param return all matching users."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        comma_ids = ",".join(ids[:3])
        resp = client.get(
            "/cs/user-management/entities/users/v1",
            headers=headers,
            params={"ids": comma_ids},
        )
        assert resp.status_code == 200
        assert len(resp.json()["resources"]) == 3

    def test_get_variant_returns_same_data_as_post(self, client: TestClient) -> None:
        """GET and POST entity endpoints must return identical user data."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        target_ids = ids[:2]

        post_resp = client.post(
            "/cs/user-management/entities/users/GET/v1",
            headers=headers,
            json={"ids": target_ids},
        )
        get_resp = client.get(
            "/cs/user-management/entities/users/v1",
            headers=headers,
            params={"ids": ",".join(target_ids)},
        )

        post_users = {u["uuid"]: u for u in post_resp.json()["resources"]}
        get_users = {u["uuid"]: u for u in get_resp.json()["resources"]}
        assert post_users == get_users

    def test_response_envelope_structure(self, client: TestClient) -> None:
        """GET entity response must contain meta.powered_by, trace_id, resources, errors."""
        headers = _cs_auth(client)
        ids = self._get_all_user_ids(client, headers)
        resp = client.get(
            "/cs/user-management/entities/users/v1",
            headers=headers,
            params={"ids": ids[0]},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert "resources" in body
        assert body["errors"] == []

    def test_requires_auth(self, client: TestClient) -> None:
        """Unauthenticated GET must be rejected with 401."""
        resp = client.get(
            "/cs/user-management/entities/users/v1",
            params={"ids": "some-id"},
        )
        assert resp.status_code == 401
