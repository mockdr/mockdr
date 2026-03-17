"""Integration tests for CrowdStrike Host Groups endpoints.

Verifies combined listing, entity retrieval, group creation, deletion,
member management, and response structure.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestListHostGroups:
    """Tests for GET /cs/devices/combined/host-groups/v1."""

    def test_combined_list_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/devices/combined/host-groups/v1", headers=headers)
        assert resp.status_code == 200

    def test_combined_list_returns_5_groups(self, client: TestClient) -> None:
        """Seeder creates 5 host groups."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 200},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 5

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/devices/combined/host-groups/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert body["errors"] == []

    def test_combined_returns_full_entities(self, client: TestClient) -> None:
        """Combined endpoint returns full group objects, not just IDs."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group = resp.json()["resources"][0]
        assert isinstance(group, dict)
        assert "id" in group
        assert "name" in group
        assert "description" in group

    def test_group_entity_has_required_fields(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group = resp.json()["resources"][0]
        required_fields = [
            "id", "name", "description", "group_type",
            "assignment_rule", "created_by", "created_timestamp",
            "modified_by", "modified_timestamp",
        ]
        for field in required_fields:
            assert field in group, f"Required field '{field}' missing from host group"

    def test_pagination(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"offset": 0, "limit": 2},
        )
        r2 = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"offset": 2, "limit": 2},
        )
        ids1 = {g["id"] for g in r1.json()["resources"]}
        ids2 = {g["id"] for g in r2.json()["resources"]}
        assert ids1.isdisjoint(ids2)


class TestGetHostGroupEntities:
    """Tests for GET /cs/devices/entities/host-groups/v1."""

    def test_get_group_by_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get a group ID from combined listing
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        resp = client.get(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": group_id},
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert resources[0]["id"] == group_id

    def test_get_multiple_groups(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 3},
        )
        group_ids = [g["id"] for g in list_resp.json()["resources"]]

        resp = client.get(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": ",".join(group_ids)},
        )
        assert len(resp.json()["resources"]) == 3

    def test_nonexistent_group_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": "nonexistent-group-id"},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestCreateHostGroup:
    """Tests for POST /cs/devices/entities/host-groups/v1."""

    def test_create_group_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            json={
                "name": "Test Group",
                "description": "A test host group",
                "group_type": "static",
            },
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        created = resources[0]
        assert created["name"] == "Test Group"
        assert created["description"] == "A test host group"
        assert created["group_type"] == "static"

    def test_created_group_appears_in_listing(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Create
        create_resp = client.post(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            json={"name": "New Group", "description": "Newly created"},
        )
        created_id = create_resp.json()["resources"][0]["id"]

        # List should show 6 total now
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 200},
        )
        assert list_resp.json()["meta"]["pagination"]["total"] == 6

        # Fetch by ID
        entity_resp = client.get(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": created_id},
        )
        assert entity_resp.json()["resources"][0]["name"] == "New Group"

    def test_create_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            json={"name": "Envelope Test Group"},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert body["errors"] == []


class TestDeleteHostGroup:
    """Tests for DELETE /cs/devices/entities/host-groups/v1."""

    def test_delete_group_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        resp = client.delete(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": group_id},
        )
        assert resp.status_code == 200

    def test_deleted_group_no_longer_in_listing(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        client.delete(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": group_id},
        )

        # Should be 4 groups now
        list_resp2 = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 200},
        )
        assert list_resp2.json()["meta"]["pagination"]["total"] == 4

    def test_delete_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        resp = client.delete(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            params={"ids": group_id},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert body["errors"] == []


class TestGroupMemberActions:
    """Tests for POST /cs/devices/entities/host-group-actions/v1."""

    def test_add_host_to_group(self, client: TestClient) -> None:
        """Add a host to a group via add-hosts action."""
        headers = _cs_auth(client)
        # Create a fresh static group
        create_resp = client.post(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            json={"name": "Member Test Group", "group_type": "static"},
        )
        group_id = create_resp.json()["resources"][0]["id"]

        # Get a host ID
        host_query = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 1},
        )
        host_id = host_query.json()["resources"][0]

        resp = client.post(
            "/cs/devices/entities/host-group-actions/v1",
            headers=headers,
            params={"action_name": "add-hosts"},
            json={
                "ids": [group_id],
                "action_parameters": [{
                    "name": "filter",
                    "value": f"device_id:['{host_id}']",
                }],
            },
        )
        assert resp.status_code == 200
        assert len(resp.json()["resources"]) == 1

    def test_remove_host_from_group(self, client: TestClient) -> None:
        """Remove a host from a group via remove-hosts action."""
        headers = _cs_auth(client)
        # Create group and add a host
        create_resp = client.post(
            "/cs/devices/entities/host-groups/v1",
            headers=headers,
            json={"name": "Remove Test Group", "group_type": "static"},
        )
        group_id = create_resp.json()["resources"][0]["id"]

        host_query = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 1},
        )
        host_id = host_query.json()["resources"][0]

        # Add host
        client.post(
            "/cs/devices/entities/host-group-actions/v1",
            headers=headers,
            params={"action_name": "add-hosts"},
            json={
                "ids": [group_id],
                "action_parameters": [{
                    "name": "filter",
                    "value": f"device_id:['{host_id}']",
                }],
            },
        )

        # Remove host
        resp = client.post(
            "/cs/devices/entities/host-group-actions/v1",
            headers=headers,
            params={"action_name": "remove-hosts"},
            json={
                "ids": [group_id],
                "action_parameters": [{
                    "name": "filter",
                    "value": f"device_id:['{host_id}']",
                }],
            },
        )
        assert resp.status_code == 200

    def test_invalid_action_returns_400(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        resp = client.post(
            "/cs/devices/entities/host-group-actions/v1",
            headers=headers,
            params={"action_name": "invalid-action"},
            json={"ids": [group_id], "action_parameters": []},
        )
        assert resp.status_code == 400


class TestListGroupMembers:
    """Tests for GET /cs/devices/combined/host-group-members/v1."""

    def test_list_members_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get a group with members (seeded groups have assigned hosts)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 5},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        resp = client.get(
            "/cs/devices/combined/host-group-members/v1",
            headers=headers,
            params={"id": group_id},
        )
        assert resp.status_code == 200

    def test_list_members_returns_host_entities(self, client: TestClient) -> None:
        """Members endpoint returns full host objects."""
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 5},
        )
        # Try each group until we find one with members
        for group in list_resp.json()["resources"]:
            resp = client.get(
                "/cs/devices/combined/host-group-members/v1",
                headers=headers,
                params={"id": group["id"]},
            )
            resources = resp.json()["resources"]
            if resources:
                host = resources[0]
                assert isinstance(host, dict)
                assert "device_id" in host
                assert "hostname" in host
                break

    def test_list_members_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        list_resp = client.get(
            "/cs/devices/combined/host-groups/v1",
            headers=headers,
            params={"limit": 1},
        )
        group_id = list_resp.json()["resources"][0]["id"]

        resp = client.get(
            "/cs/devices/combined/host-group-members/v1",
            headers=headers,
            params={"id": group_id},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "pagination" in body["meta"]
        assert body["errors"] == []
