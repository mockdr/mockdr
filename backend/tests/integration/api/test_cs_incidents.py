"""Integration tests for CrowdStrike Incidents endpoints.

Verifies incident queries, entity retrieval, action-based updates
(status, tags), and response structure.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestQueryIncidents:
    """Tests for GET /cs/incidents/queries/incidents/v1."""

    def test_query_incident_ids_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/incidents/queries/incidents/v1", headers=headers)
        assert resp.status_code == 200

    def test_query_returns_15_incidents(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 200},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 15

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/incidents/queries/incidents/v1", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert body["errors"] == []

    def test_resources_are_incident_id_strings(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 5},
        )
        for rid in resp.json()["resources"]:
            assert isinstance(rid, str)
            assert rid.startswith("inc:")

    def test_pagination(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"offset": 0, "limit": 5},
        )
        r2 = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"offset": 5, "limit": 5},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2)


class TestGetIncidentEntities:
    """Tests for POST /cs/incidents/entities/incidents/GET/v1."""

    def test_get_incident_by_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert resources[0]["incident_id"] == inc_id

    def test_incident_has_required_fields(self, client: TestClient) -> None:
        """Incident entity must include key fields from the CS schema."""
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        incident = resp.json()["resources"][0]
        required_fields = [
            "incident_id", "cid", "fine_score", "status", "state",
            "hosts", "host_ids", "name", "description", "tags",
            "created", "modified_timestamp", "tactics", "techniques",
        ]
        for field in required_fields:
            assert field in incident, f"Required field '{field}' missing from incident"

    def test_incident_hosts_is_list_of_dicts(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        incident = resp.json()["resources"][0]
        assert isinstance(incident["hosts"], list)
        assert len(incident["hosts"]) > 0
        host = incident["hosts"][0]
        assert "device_id" in host
        assert "hostname" in host

    def test_incident_status_is_integer(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        incident = resp.json()["resources"][0]
        assert isinstance(incident["status"], int)
        assert incident["status"] in (20, 25, 30, 40)

    def test_nonexistent_incident_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": ["inc:nonexistent:999"]},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestIncidentActions:
    """Tests for POST /cs/incidents/entities/incident-actions/v1."""

    def test_update_status(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incident-actions/v1",
            headers=headers,
            json={
                "ids": [inc_id],
                "action_parameters": [
                    {"name": "update_status", "value": "40"},
                ],
            },
        )
        assert resp.status_code == 200
        assert len(resp.json()["resources"]) == 1

        # Verify the status changed
        entity_resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        incident = entity_resp.json()["resources"][0]
        assert incident["status"] == 40
        assert incident["state"] == "closed"

    def test_add_tag(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incident-actions/v1",
            headers=headers,
            json={
                "ids": [inc_id],
                "action_parameters": [
                    {"name": "add_tag", "value": "test-tag-123"},
                ],
            },
        )
        assert resp.status_code == 200

        # Verify tag was added
        entity_resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        incident = entity_resp.json()["resources"][0]
        assert "test-tag-123" in incident["tags"]

    def test_delete_tag(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        # Add a tag first
        client.post(
            "/cs/incidents/entities/incident-actions/v1",
            headers=headers,
            json={
                "ids": [inc_id],
                "action_parameters": [
                    {"name": "add_tag", "value": "removable-tag"},
                ],
            },
        )

        # Now delete it
        resp = client.post(
            "/cs/incidents/entities/incident-actions/v1",
            headers=headers,
            json={
                "ids": [inc_id],
                "action_parameters": [
                    {"name": "delete_tag", "value": "removable-tag"},
                ],
            },
        )
        assert resp.status_code == 200

        entity_resp = client.post(
            "/cs/incidents/entities/incidents/GET/v1",
            headers=headers,
            json={"ids": [inc_id]},
        )
        assert "removable-tag" not in entity_resp.json()["resources"][0]["tags"]

    def test_action_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/incidents/queries/incidents/v1",
            headers=headers,
            params={"limit": 1},
        )
        inc_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/incidents/entities/incident-actions/v1",
            headers=headers,
            json={
                "ids": [inc_id],
                "action_parameters": [
                    {"name": "update_status", "value": "30"},
                ],
            },
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []
