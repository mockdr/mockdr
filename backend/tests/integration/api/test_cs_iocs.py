"""Integration tests for CrowdStrike IOC (Indicator of Compromise) endpoints.

Verifies combined search, entity retrieval, IOC creation, update, deletion,
and response structure.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestSearchIocs:
    """Tests for GET /cs/iocs/combined/indicator/v1."""

    def test_combined_search_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/iocs/combined/indicator/v1", headers=headers)
        assert resp.status_code == 200

    def test_combined_search_returns_20_iocs(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 200},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 20

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/iocs/combined/indicator/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert body["errors"] == []

    def test_combined_returns_full_entities(self, client: TestClient) -> None:
        """Combined endpoint should return full IOC objects, not just IDs."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 5},
        )
        resources = resp.json()["resources"]
        assert len(resources) > 0
        ioc = resources[0]
        assert isinstance(ioc, dict)
        assert "id" in ioc
        assert "type" in ioc
        assert "value" in ioc

    def test_ioc_entity_has_required_fields(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc = resp.json()["resources"][0]
        required_fields = [
            "id", "type", "value", "action", "severity",
            "platforms", "created_on", "created_by",
            "modified_on", "modified_by", "applied_globally",
        ]
        for field in required_fields:
            assert field in ioc, f"Required field '{field}' missing from IOC"

    def test_pagination_offset_limit(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"offset": 0, "limit": 5},
        )
        r2 = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"offset": 5, "limit": 5},
        )
        ids1 = {r["id"] for r in r1.json()["resources"]}
        ids2 = {r["id"] for r in r2.json()["resources"]}
        assert ids1.isdisjoint(ids2)


class TestGetIocEntities:
    """Tests for GET /cs/iocs/entities/indicators/v1."""

    def test_get_ioc_by_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get an IOC ID from combined search
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc_id = search_resp.json()["resources"][0]["id"]

        resp = client.get(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert resources[0]["id"] == ioc_id

    def test_get_multiple_iocs_by_comma_separated_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 3},
        )
        ioc_ids = [r["id"] for r in search_resp.json()["resources"]]

        resp = client.get(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": ",".join(ioc_ids)},
        )
        assert len(resp.json()["resources"]) == 3

    def test_nonexistent_ioc_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": "nonexistent-ioc-id-12345"},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestCreateIoc:
    """Tests for POST /cs/iocs/entities/indicators/v1."""

    def test_create_ioc_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            json={
                "indicators": [{
                    "type": "domain",
                    "value": "malware-c2.evil.com",
                    "action": "detect",
                    "severity": "high",
                    "description": "Known C2 domain",
                    "platforms": ["windows", "mac"],
                    "applied_globally": True,
                }],
            },
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        created = resources[0]
        assert created["type"] == "domain"
        assert created["value"] == "malware-c2.evil.com"
        assert created["action"] == "detect"

    def test_created_ioc_appears_in_search(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Create
        create_resp = client.post(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            json={
                "indicators": [{
                    "type": "ipv4",
                    "value": "198.51.100.99",
                    "action": "detect",
                }],
            },
        )
        created_id = create_resp.json()["resources"][0]["id"]

        # Search should show 21 total now
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 200},
        )
        assert search_resp.json()["meta"]["pagination"]["total"] == 21

        # Fetch by ID
        entity_resp = client.get(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": created_id},
        )
        assert entity_resp.json()["resources"][0]["value"] == "198.51.100.99"

    def test_create_ioc_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            json={"indicators": [{"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e", "action": "no_action"}]},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert body["errors"] == []


class TestUpdateIoc:
    """Tests for PATCH /cs/iocs/entities/indicators/v1."""

    def test_update_ioc_severity(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get an existing IOC
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc = search_resp.json()["resources"][0]
        ioc_id = ioc["id"]

        resp = client.patch(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            json={
                "indicators": [{
                    "id": ioc_id,
                    "severity": "critical",
                    "description": "Updated description",
                }],
            },
        )
        assert resp.status_code == 200
        updated = resp.json()["resources"][0]
        assert updated["severity"] == "critical"
        assert updated["description"] == "Updated description"

    def test_update_nonexistent_ioc_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.patch(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            json={
                "indicators": [{
                    "id": "nonexistent-id",
                    "severity": "high",
                }],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestDeleteIoc:
    """Tests for DELETE /cs/iocs/entities/indicators/v1."""

    def test_delete_ioc_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get an IOC ID
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc_id = search_resp.json()["resources"][0]["id"]

        resp = client.delete(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        assert resp.status_code == 200

    def test_deleted_ioc_no_longer_in_search(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc_id = search_resp.json()["resources"][0]["id"]

        # Delete
        client.delete(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": ioc_id},
        )

        # Verify count decreased
        search_resp2 = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 200},
        )
        assert search_resp2.json()["meta"]["pagination"]["total"] == 19

        # Verify entity no longer exists
        entity_resp = client.get(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        assert entity_resp.json()["resources"] == []

    def test_delete_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        search_resp = client.get(
            "/cs/iocs/combined/indicator/v1",
            headers=headers,
            params={"limit": 1},
        )
        ioc_id = search_resp.json()["resources"][0]["id"]

        resp = client.delete(
            "/cs/iocs/entities/indicators/v1",
            headers=headers,
            params={"ids": ioc_id},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert body["errors"] == []
