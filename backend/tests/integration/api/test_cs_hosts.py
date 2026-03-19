"""Integration tests for CrowdStrike Hosts/Devices endpoints.

Verifies host queries, entity retrieval, FQL filtering, pagination,
device actions, and response envelope structure.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestQueryHosts:
    """Tests for GET /cs/devices/queries/devices/v1."""

    def test_query_all_host_ids_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers)
        assert resp.status_code == 200

    def test_query_all_returns_60_hosts(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 200},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 60

    def test_response_envelope_structure(self, client: TestClient) -> None:
        """Response must have meta.query_time, meta.powered_by, meta.trace_id."""
        headers = _cs_auth(client)
        resp = client.get("/cs/devices/queries/devices/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "resources" in body
        assert "errors" in body
        assert body["errors"] == []

    def test_pagination_metadata(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 10, "offset": 0},
        )
        body = resp.json()
        pagination = body["meta"]["pagination"]
        assert pagination["offset"] == 0
        assert pagination["limit"] == 10
        assert pagination["total"] == 60
        assert len(body["resources"]) == 10

    def test_resources_are_string_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 5},
        )
        for resource in resp.json()["resources"]:
            assert isinstance(resource, str)

    def test_fql_filter_platform_windows(self, client: TestClient) -> None:
        """FQL filter platform_name:'Windows' returns only Windows hosts."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"filter": "platform_name:'Windows'", "limit": 200},
        )
        body = resp.json()
        assert resp.status_code == 200
        # Verify by fetching entities for the returned IDs
        if body["resources"]:
            entity_resp = client.post(
                "/cs/devices/entities/devices/v2",
                headers=headers,
                json={"ids": body["resources"][:5]},
            )
            for host in entity_resp.json()["resources"]:
                assert host["platform_name"] == "Windows"

    def test_fql_filter_status_normal(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"filter": "status:'normal'", "limit": 200},
        )
        body = resp.json()
        assert resp.status_code == 200
        # All returned hosts should have normal status
        if body["resources"]:
            entity_resp = client.post(
                "/cs/devices/entities/devices/v2",
                headers=headers,
                json={"ids": body["resources"][:5]},
            )
            for host in entity_resp.json()["resources"]:
                assert host["status"] == "normal"

    def test_pagination_offset_limit(self, client: TestClient) -> None:
        """Offset and limit produce disjoint pages."""
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"offset": 0, "limit": 10},
        )
        r2 = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"offset": 10, "limit": 10},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2), "Paginated pages should not overlap"


class TestGetHostEntities:
    """Tests for POST /cs/devices/entities/devices/v2."""

    def test_get_host_by_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get a host ID first
        query_resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 1},
        )
        host_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": [host_id]},
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert resources[0]["device_id"] == host_id

    def test_host_entity_has_required_fields(self, client: TestClient) -> None:
        """Host entity must include key fields matching CS API schema."""
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 1},
        )
        host_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": [host_id]},
        )
        host = resp.json()["resources"][0]
        required_fields = [
            "device_id", "cid", "hostname", "platform_name",
            "os_version", "agent_version", "status", "local_ip",
            "external_ip", "first_seen", "last_seen", "tags",
            "policies", "device_policies", "product_type_desc",
        ]
        for field in required_fields:
            assert field in host, f"Required field '{field}' missing from host entity"

    def test_get_multiple_hosts(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 3},
        )
        host_ids = query_resp.json()["resources"]

        resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": host_ids},
        )
        assert len(resp.json()["resources"]) == 3

    def test_nonexistent_host_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": ["nonexistent-id-12345"]},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestDeviceActions:
    """Tests for POST /cs/devices/entities/devices-actions/v2."""

    def _get_normal_host_id(self, client: TestClient, headers: dict) -> str:
        """Return a host ID with status 'normal'."""
        query_resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"filter": "status:'normal'", "limit": 1},
        )
        return query_resp.json()["resources"][0]

    def test_contain_host(self, client: TestClient) -> None:
        """Containment action sets status to containment_pending."""
        headers = _cs_auth(client)
        host_id = self._get_normal_host_id(client, headers)

        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "contain"},
            json={"ids": [host_id]},
        )
        assert resp.status_code == 200

        # Verify the host status changed
        entity_resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": [host_id]},
        )
        host = entity_resp.json()["resources"][0]
        assert host["status"] == "containment_pending"

    def test_lift_containment(self, client: TestClient) -> None:
        """Lifting containment sets status back to normal."""
        headers = _cs_auth(client)
        host_id = self._get_normal_host_id(client, headers)

        # First contain
        client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "contain"},
            json={"ids": [host_id]},
        )

        # Then lift
        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "lift_containment"},
            json={"ids": [host_id]},
        )
        assert resp.status_code == 200

        entity_resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": [host_id]},
        )
        assert entity_resp.json()["resources"][0]["status"] == "normal"

    def test_invalid_action_name_returns_400(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/devices/queries/devices/v1",
            headers=headers,
            params={"limit": 1},
        )
        host_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "invalid_action"},
            json={"ids": [host_id]},
        )
        assert resp.status_code == 400

    def test_contain_action_response_envelope(self, client: TestClient) -> None:
        """Action response must have proper CS envelope."""
        headers = _cs_auth(client)
        host_id = self._get_normal_host_id(client, headers)

        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "contain"},
            json={"ids": [host_id]},
        )
        body = resp.json()
        assert "meta" in body
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "resources" in body
        assert "errors" in body

    def test_hide_host_removes_from_listing(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        host_id = self._get_normal_host_id(client, headers)

        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "hide_host"},
            json={"ids": [host_id]},
        )
        assert resp.status_code == 200

        # Host should no longer appear in entities
        entity_resp = client.post(
            "/cs/devices/entities/devices/v2",
            headers=headers,
            json={"ids": [host_id]},
        )
        assert entity_resp.json()["resources"] == []

    def test_missing_ids_returns_400(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/devices/entities/devices-actions/v2",
            headers=headers,
            params={"action_name": "contain"},
            json={"ids": []},
        )
        assert resp.status_code == 400
