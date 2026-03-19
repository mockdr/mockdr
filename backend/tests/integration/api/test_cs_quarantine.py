"""Integration tests for CrowdStrike Quarantine endpoints.

Verifies quarantined-file ID queries, entity retrieval, FQL filtering,
pagination, state-changing actions, response envelope structure, and RBAC.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _cs_viewer_auth(client: TestClient) -> dict[str, str]:
    """Authenticate as viewer and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-viewer-client",
        "client_secret": "cs-mock-viewer-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestQueryQuarantinedFiles:
    """Tests for GET /cs/quarantine/queries/quarantined-files/v1."""

    def test_query_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
        )
        assert resp.status_code == 200

    def test_response_envelope_structure(self, client: TestClient) -> None:
        """Response must contain meta with query_time, powered_by, trace_id, pagination."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
        )
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert "resources" in body
        assert "errors" in body
        assert body["errors"] == []

    def test_query_returns_up_to_15_file_ids(self, client: TestClient) -> None:
        """Seeder creates exactly 15 quarantined files."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"limit": 500},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 15

    def test_resources_are_string_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"limit": 5},
        )
        for resource_id in resp.json()["resources"]:
            assert isinstance(resource_id, str)
            assert len(resource_id) > 0

    def test_pagination_offset_limit_produces_disjoint_pages(self, client: TestClient) -> None:
        """Two consecutive pages must not share any IDs."""
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"offset": 0, "limit": 7},
        )
        r2 = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"offset": 7, "limit": 7},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2), "Paginated pages must not overlap"

    def test_pagination_metadata_reflects_params(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"offset": 5, "limit": 4},
        )
        pagination = resp.json()["meta"]["pagination"]
        assert pagination["offset"] == 5
        assert pagination["limit"] == 4
        assert pagination["total"] == 15
        assert len(resp.json()["resources"]) == 4

    def test_fql_filter_by_state_quarantined(self, client: TestClient) -> None:
        """FQL filter state:'quarantined' returns only quarantined files."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"filter": "state:'quarantined'", "limit": 500},
        )
        assert resp.status_code == 200
        body = resp.json()
        # Verify by fetching entities for returned IDs
        if body["resources"]:
            ids_param = ",".join(body["resources"][:5])
            entity_resp = client.get(
                "/cs/quarantine/entities/quarantined-files/v1",
                headers=headers,
                params={"ids": ids_param},
            )
            for qf in entity_resp.json()["resources"]:
                assert qf["state"] == "quarantined"

    def test_auth_required_returns_401_without_token(self, client: TestClient) -> None:
        resp = client.get("/cs/quarantine/queries/quarantined-files/v1")
        assert resp.status_code == 401


class TestGetQuarantinedFileEntities:
    """Tests for GET /cs/quarantine/entities/quarantined-files/v1?ids=..."""

    def test_get_entities_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"limit": 1},
        )
        file_id = query_resp.json()["resources"][0]

        resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": file_id},
        )
        assert resp.status_code == 200

    def test_entity_has_required_fields(self, client: TestClient) -> None:
        """Quarantined file entity must include all expected domain fields."""
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"limit": 1},
        )
        file_id = query_resp.json()["resources"][0]

        resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": file_id},
        )
        qf = resp.json()["resources"][0]
        required_fields = [
            "id", "cid", "aid", "sha256", "filename", "paths",
            "state", "hostname", "username", "date_created",
            "date_updated", "detect_ids",
        ]
        for field in required_fields:
            assert field in qf, f"Required field '{field}' missing from quarantined file entity"

    def test_entity_id_matches_requested_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"limit": 1},
        )
        file_id = query_resp.json()["resources"][0]

        resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": file_id},
        )
        assert resp.json()["resources"][0]["id"] == file_id

    def test_get_multiple_entities_by_comma_separated_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"limit": 3},
        )
        ids = query_resp.json()["resources"]
        ids_param = ",".join(ids)

        resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": ids_param},
        )
        assert resp.status_code == 200
        assert len(resp.json()["resources"]) == 3

    def test_nonexistent_id_returns_empty_resources(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": "nonexistent-file-id-00000"},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []

    def test_auth_required_returns_401_without_token(self, client: TestClient) -> None:
        resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            params={"ids": "some-id"},
        )
        assert resp.status_code == 401


class TestActionQuarantinedFiles:
    """Tests for PATCH /cs/quarantine/entities/quarantined-files/v1."""

    def _get_quarantined_id(self, client: TestClient, headers: dict) -> str:
        """Return an ID of a file currently in 'quarantined' state."""
        resp = client.get(
            "/cs/quarantine/queries/quarantined-files/v1",
            headers=headers,
            params={"filter": "state:'quarantined'", "limit": 1},
        )
        resources = resp.json()["resources"]
        assert resources, "No quarantined files available for action test"
        return resources[0]

    def test_release_action_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        file_id = self._get_quarantined_id(client, headers)

        resp = client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            json={"ids": [file_id], "action": "release"},
        )
        assert resp.status_code == 200

    def test_release_action_changes_state_to_released(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        file_id = self._get_quarantined_id(client, headers)

        client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            json={"ids": [file_id], "action": "release"},
        )

        entity_resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": file_id},
        )
        assert entity_resp.json()["resources"][0]["state"] == "released"

    def test_delete_action_changes_state_to_deleted(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        file_id = self._get_quarantined_id(client, headers)

        client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            json={"ids": [file_id], "action": "delete"},
        )

        entity_resp = client.get(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            params={"ids": file_id},
        )
        assert entity_resp.json()["resources"][0]["state"] == "deleted"

    def test_action_response_envelope_structure(self, client: TestClient) -> None:
        """Action response must have the standard CS meta + resources + errors envelope."""
        headers = _cs_auth(client)
        file_id = self._get_quarantined_id(client, headers)

        resp = client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            json={"ids": [file_id], "action": "release"},
        )
        body = resp.json()
        assert "meta" in body
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert "resources" in body
        assert body["errors"] == []

    def test_action_response_resources_contain_affected_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        file_id = self._get_quarantined_id(client, headers)

        resp = client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=headers,
            json={"ids": [file_id], "action": "release"},
        )
        affected_ids = [r["id"] for r in resp.json()["resources"]]
        assert file_id in affected_ids

    def test_auth_required_returns_401_without_token(self, client: TestClient) -> None:
        resp = client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            json={"ids": ["some-id"], "action": "release"},
        )
        assert resp.status_code == 401

    def test_viewer_role_returns_403_on_patch(self, client: TestClient) -> None:
        """Viewer role must be denied write access with 403."""
        viewer_headers = _cs_viewer_auth(client)
        admin_headers = _cs_auth(client)
        file_id = self._get_quarantined_id(client, admin_headers)

        resp = client.patch(
            "/cs/quarantine/entities/quarantined-files/v1",
            headers=viewer_headers,
            json={"ids": [file_id], "action": "release"},
        )
        assert resp.status_code == 403
