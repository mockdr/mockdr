"""Integration tests for CrowdStrike Legacy IOC endpoints.

Verifies the deprecated /indicators/ paths that older XSOAR integrations use.
These endpoints share the same cs_iocs store as the modern /iocs/ paths.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestQueryLegacyIocIds:
    """Tests for GET /cs/indicators/queries/iocs/v1."""

    def test_query_ioc_ids_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/indicators/queries/iocs/v1", headers=headers)
        assert resp.status_code == 200

    def test_resources_is_list_of_strings(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/indicators/queries/iocs/v1", headers=headers)
        resources = resp.json()["resources"]
        assert isinstance(resources, list)
        assert all(isinstance(r, str) for r in resources)

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/indicators/queries/iocs/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert body["errors"] == []

    def test_pagination_metadata(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/queries/iocs/v1",
            headers=headers,
            params={"limit": 5, "offset": 0},
        )
        pagination = resp.json()["meta"]["pagination"]
        assert pagination["offset"] == 0
        assert pagination["limit"] == 5

    def test_returns_seeded_ioc_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/queries/iocs/v1",
            headers=headers,
            params={"limit": 200},
        )
        assert resp.json()["meta"]["pagination"]["total"] == 20

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.get("/cs/indicators/queries/iocs/v1")
        assert resp.status_code == 401


class TestGetLegacyIocEntities:
    """Tests for GET /cs/indicators/entities/iocs/v1."""

    def _first_ioc_id(self, client: TestClient, headers: dict) -> str:
        resp = client.get(
            "/cs/indicators/queries/iocs/v1",
            headers=headers,
            params={"limit": 1},
        )
        return resp.json()["resources"][0]

    def test_get_entity_by_id_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc_id = self._first_ioc_id(client, headers)
        resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        assert resp.status_code == 200

    def test_get_entity_returns_full_object(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc_id = self._first_ioc_id(client, headers)
        resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        resources = resp.json()["resources"]
        assert len(resources) == 1
        ioc = resources[0]
        for field in ("id", "type", "value", "action"):
            assert field in ioc, f"Required field '{field}' missing from IOC entity"

    def test_get_multiple_ids_comma_separated(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ids_resp = client.get(
            "/cs/indicators/queries/iocs/v1",
            headers=headers,
            params={"limit": 3},
        )
        ids = ids_resp.json()["resources"]
        resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ",".join(ids)},
        )
        assert resp.status_code == 200
        assert len(resp.json()["resources"]) == 3

    def test_nonexistent_id_returns_empty_resources(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": "no-such-ioc-id-00000000"},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc_id = self._first_ioc_id(client, headers)
        resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.get("/cs/indicators/entities/iocs/v1", params={"ids": "x"})
        assert resp.status_code == 401


class TestCreateLegacyIoc:
    """Tests for POST /cs/indicators/entities/iocs/v1."""

    def test_create_ioc_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={
                "indicators": [{
                    "type": "sha256",
                    "value": "aabbcc" + "0" * 58,
                    "action": "detect",
                    "severity": "medium",
                }],
            },
        )
        assert resp.status_code == 200

    def test_create_returns_created_ioc(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={
                "indicators": [{
                    "type": "domain",
                    "value": "legacy-malware.example.com",
                    "action": "prevent",
                    "severity": "high",
                }],
            },
        )
        resources = resp.json()["resources"]
        assert len(resources) == 1
        created = resources[0]
        assert created["type"] == "domain"
        assert created["value"] == "legacy-malware.example.com"
        assert created["action"] == "prevent"

    def test_created_ioc_retrievable_via_entities_endpoint(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        create_resp = client.post(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={
                "indicators": [{
                    "type": "ipv4",
                    "value": "203.0.113.42",
                    "action": "detect",
                }],
            },
        )
        created_id = create_resp.json()["resources"][0]["id"]

        entity_resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": created_id},
        )
        assert entity_resp.json()["resources"][0]["value"] == "203.0.113.42"

    def test_create_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={"indicators": [{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427f", "action": "no_action"}]},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.post(
            "/cs/indicators/entities/iocs/v1",
            json={"indicators": [{"type": "domain", "value": "x.com", "action": "detect"}]},
        )
        assert resp.status_code == 401


class TestUpdateLegacyIoc:
    """Tests for PATCH /cs/indicators/entities/iocs/v1."""

    def _get_first_ioc(self, client: TestClient, headers: dict) -> dict:
        ids_resp = client.get(
            "/cs/indicators/queries/iocs/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc_id = ids_resp.json()["resources"][0]
        entity_resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        return entity_resp.json()["resources"][0]

    def test_update_ioc_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc = self._get_first_ioc(client, headers)
        resp = client.patch(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={"id": ioc["id"], "action": "prevent"},
        )
        assert resp.status_code == 200

    def test_update_modifies_action_field(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc = self._get_first_ioc(client, headers)
        resp = client.patch(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={"id": ioc["id"], "action": "prevent"},
        )
        updated = resp.json()["resources"][0]
        assert updated["action"] == "prevent"

    def test_update_nonexistent_ioc_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.patch(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={"id": "does-not-exist-xyz", "action": "prevent"},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.patch(
            "/cs/indicators/entities/iocs/v1",
            json={"id": "some-id", "action": "prevent"},
        )
        assert resp.status_code == 401


class TestDeleteLegacyIoc:
    """Tests for DELETE /cs/indicators/entities/iocs/v1."""

    def _create_ioc(self, client: TestClient, headers: dict, value: str) -> str:
        resp = client.post(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            json={"indicators": [{"type": "domain", "value": value, "action": "detect"}]},
        )
        return resp.json()["resources"][0]["id"]

    def test_delete_ioc_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc_id = self._create_ioc(client, headers, "delete-test-1.example.com")
        resp = client.delete(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        assert resp.status_code == 200

    def test_deleted_ioc_no_longer_retrievable(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc_id = self._create_ioc(client, headers, "delete-test-2.example.com")

        client.delete(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )

        entity_resp = client.get(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        assert entity_resp.json()["resources"] == []

    def test_delete_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        ioc_id = self._create_ioc(client, headers, "delete-test-3.example.com")
        resp = client.delete(
            "/cs/indicators/entities/iocs/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.delete(
            "/cs/indicators/entities/iocs/v1",
            params={"ids": "some-id"},
        )
        assert resp.status_code == 401


class TestDeviceCountForIoc:
    """Tests for GET /cs/indicators/aggregates/devices-count/v1."""

    def test_device_count_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/aggregates/devices-count/v1",
            headers=headers,
            params={"type": "sha256", "value": "abc123def456"},
        )
        assert resp.status_code == 200

    def test_device_count_returns_numeric_count(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/aggregates/devices-count/v1",
            headers=headers,
            params={"type": "sha256", "value": "abc123def456"},
        )
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert isinstance(resources[0]["device_count"], int)
        assert resources[0]["device_count"] >= 1

    def test_device_count_resource_has_type_and_value(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/aggregates/devices-count/v1",
            headers=headers,
            params={"type": "domain", "value": "evil.example.com"},
        )
        resource = resp.json()["resources"][0]
        assert resource["type"] == "domain"

    def test_device_count_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/aggregates/devices-count/v1",
            headers=headers,
            params={"type": "ipv4", "value": "1.2.3.4"},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.get(
            "/cs/indicators/aggregates/devices-count/v1",
            params={"type": "sha256", "value": "abc123"},
        )
        assert resp.status_code == 401


class TestProcessesRanOn:
    """Tests for GET /cs/indicators/queries/processes/v1."""

    def test_processes_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/queries/processes/v1",
            headers=headers,
            params={"type": "sha256", "value": "abc123def456"},
        )
        assert resp.status_code == 200

    def test_processes_returns_list_of_process_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/queries/processes/v1",
            headers=headers,
            params={"type": "sha256", "value": "abc123def456"},
        )
        resources = resp.json()["resources"]
        assert isinstance(resources, list)
        assert len(resources) >= 1
        assert all(isinstance(pid, str) for pid in resources)

    def test_processes_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/queries/processes/v1",
            headers=headers,
            params={"type": "domain", "value": "evil.example.com"},
        )
        body = resp.json()
        meta = body["meta"]
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert body["errors"] == []

    def test_processes_pagination_in_meta(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/indicators/queries/processes/v1",
            headers=headers,
            params={"type": "ipv4", "value": "198.51.100.1"},
        )
        pagination = resp.json()["meta"]["pagination"]
        assert "total" in pagination
        assert isinstance(pagination["total"], int)

    def test_auth_required(self, client: TestClient) -> None:
        resp = client.get(
            "/cs/indicators/queries/processes/v1",
            params={"type": "sha256", "value": "abc123"},
        )
        assert resp.status_code == 401
