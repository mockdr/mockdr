"""Integration tests for CrowdStrike Process Analysis endpoint.

Verifies process entity retrieval, response envelope structure, field coverage,
deterministic output, and authentication enforcement.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


_PROCESS_ID_A = "pid:abc123:1234"
_PROCESS_ID_B = "pid:def456:5678"


class TestGetProcessEntities:
    """Tests for GET /cs/processes/entities/processes/v1."""

    def test_returns_200_for_valid_process_ids(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": _PROCESS_ID_A},
        )
        assert resp.status_code == 200

    def test_response_envelope_has_meta_powered_by_and_trace_id(self, client: TestClient) -> None:
        """Response envelope must include meta.powered_by, meta.trace_id, resources, errors."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": _PROCESS_ID_A},
        )
        body = resp.json()
        assert "meta" in body
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert "resources" in body
        assert "errors" in body
        assert body["errors"] == []

    def test_single_id_returns_one_entity(self, client: TestClient) -> None:
        """A single process ID must produce exactly one resource in the response."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": _PROCESS_ID_A},
        )
        resources = resp.json()["resources"]
        assert len(resources) == 1

    def test_multiple_ids_return_multiple_entities(self, client: TestClient) -> None:
        """Two comma-separated process IDs must produce two resource entities."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": f"{_PROCESS_ID_A},{_PROCESS_ID_B}"},
        )
        resources = resp.json()["resources"]
        assert len(resources) == 2

    def test_returned_entities_match_requested_process_ids(self, client: TestClient) -> None:
        """Each returned entity's process_id must correspond to a requested ID."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": f"{_PROCESS_ID_A},{_PROCESS_ID_B}"},
        )
        returned_ids = {e["process_id"] for e in resp.json()["resources"]}
        assert returned_ids == {_PROCESS_ID_A, _PROCESS_ID_B}

    def test_entity_has_all_expected_fields(self, client: TestClient) -> None:
        """Each process entity must expose the full set of documented fields."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": _PROCESS_ID_A},
        )
        entity = resp.json()["resources"][0]
        expected_fields = [
            "process_id",
            "device_id",
            "command_line",
            "file_name",
            "start_timestamp",
            "parent_process_id",
            "user_name",
            "sha256",
            "md5",
        ]
        for field in expected_fields:
            assert field in entity, f"Expected field '{field}' missing from process entity"

    def test_device_id_extracted_from_process_id(self, client: TestClient) -> None:
        """device_id must be the middle segment of the pid:<device_id>:<num> format."""
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            headers=headers,
            params={"ids": _PROCESS_ID_A},
        )
        entity = resp.json()["resources"][0]
        assert entity["device_id"] == "abc123"

    def test_output_is_deterministic_for_same_id(self, client: TestClient) -> None:
        """Calling the endpoint twice with the same ID must return identical entity data."""
        headers = _cs_auth(client)
        url = "/cs/processes/entities/processes/v1"
        params = {"ids": _PROCESS_ID_A}

        first = client.get(url, headers=headers, params=params).json()["resources"][0]
        second = client.get(url, headers=headers, params=params).json()["resources"][0]

        # trace_id is always different; compare entity fields only
        for field in ("process_id", "device_id", "command_line", "file_name",
                      "sha256", "md5", "user_name", "parent_process_id"):
            assert first[field] == second[field], (
                f"Field '{field}' differed between calls: {first[field]!r} vs {second[field]!r}"
            )

    def test_auth_required_returns_401_without_token(self, client: TestClient) -> None:
        """Requests without an Authorization header must be rejected with HTTP 401."""
        resp = client.get(
            "/cs/processes/entities/processes/v1",
            params={"ids": _PROCESS_ID_A},
        )
        assert resp.status_code == 401
