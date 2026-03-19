"""Integration tests for CrowdStrike Detections/Alerts endpoints.

Verifies detection queries, entity retrieval, FQL filtering, status updates,
behavior structure with MITRE fields, and response envelope format.
"""
from fastapi.testclient import TestClient


def _cs_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return CS Bearer headers."""
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestQueryDetections:
    """Tests for GET /cs/alerts/queries/alerts/v2."""

    def test_query_detection_ids_returns_200(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/alerts/queries/alerts/v2", headers=headers)
        assert resp.status_code == 200

    def test_query_returns_30_detections(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 200},
        )
        body = resp.json()
        assert body["meta"]["pagination"]["total"] == 30

    def test_response_envelope_structure(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get("/cs/alerts/queries/alerts/v2", headers=headers)
        body = resp.json()
        meta = body["meta"]
        assert "query_time" in meta
        assert meta["powered_by"] == "crowdstrike-api"
        assert "trace_id" in meta
        assert "pagination" in meta
        assert "resources" in body
        assert "errors" in body
        assert body["errors"] == []

    def test_resources_are_composite_id_strings(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 5},
        )
        for rid in resp.json()["resources"]:
            assert isinstance(rid, str)
            assert rid.startswith("ldt:")

    def test_fql_filter_on_status(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"filter": "status:'new'", "limit": 200},
        )
        assert resp.status_code == 200
        body = resp.json()
        # Verify by fetching entities
        if body["resources"]:
            entity_resp = client.post(
                "/cs/alerts/entities/alerts/v2",
                headers=headers,
                json={"ids": body["resources"][:5]},
            )
            for det in entity_resp.json()["resources"]:
                assert det["status"] == "new"

    def test_pagination_offset_limit(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        r1 = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"offset": 0, "limit": 10},
        )
        r2 = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"offset": 10, "limit": 10},
        )
        ids1 = set(r1.json()["resources"])
        ids2 = set(r2.json()["resources"])
        assert ids1.isdisjoint(ids2)


class TestGetDetectionEntities:
    """Tests for POST /cs/alerts/entities/alerts/v2."""

    def test_get_detection_by_composite_id(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 1},
        )
        det_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/alerts/entities/alerts/v2",
            headers=headers,
            json={"composite_ids": [det_id]},
        )
        assert resp.status_code == 200
        resources = resp.json()["resources"]
        assert len(resources) == 1
        assert resources[0]["composite_id"] == det_id

    def test_detection_has_required_fields(self, client: TestClient) -> None:
        """Detection entity must include composite_id, device, behaviors, status, severity."""
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 1},
        )
        det_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/alerts/entities/alerts/v2",
            headers=headers,
            json={"ids": [det_id]},
        )
        detection = resp.json()["resources"][0]
        required_fields = [
            "composite_id", "device", "behaviors", "max_severity",
            "max_severity_displayname", "status", "created_timestamp",
            "first_behavior", "last_behavior",
        ]
        for field in required_fields:
            assert field in detection, f"Required field '{field}' missing from detection"

    def test_detection_device_is_dict(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 1},
        )
        det_id = query_resp.json()["resources"][0]

        resp = client.post(
            "/cs/alerts/entities/alerts/v2",
            headers=headers,
            json={"ids": [det_id]},
        )
        detection = resp.json()["resources"][0]
        assert isinstance(detection["device"], dict)
        assert "device_id" in detection["device"]
        assert "hostname" in detection["device"]

    def test_detection_behaviors_have_mitre_fields(self, client: TestClient) -> None:
        """Each behavior must contain tactic, technique, and tactic_id fields."""
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 5},
        )
        det_ids = query_resp.json()["resources"]

        resp = client.post(
            "/cs/alerts/entities/alerts/v2",
            headers=headers,
            json={"ids": det_ids},
        )
        for detection in resp.json()["resources"]:
            assert isinstance(detection["behaviors"], list)
            assert len(detection["behaviors"]) > 0
            for behavior in detection["behaviors"]:
                assert "tactic" in behavior
                assert "technique" in behavior
                assert "tactic_id" in behavior
                assert "technique_id" in behavior
                assert "severity" in behavior

    def test_nonexistent_detection_returns_empty(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        resp = client.post(
            "/cs/alerts/entities/alerts/v2",
            headers=headers,
            json={"ids": ["ldt:nonexistent:999"]},
        )
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestUpdateDetections:
    """Tests for PATCH /cs/alerts/entities/alerts/v3."""

    def test_update_detection_status(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        # Get a detection ID
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 1},
        )
        det_id = query_resp.json()["resources"][0]

        resp = client.patch(
            "/cs/alerts/entities/alerts/v3",
            headers=headers,
            json={"ids": [det_id], "status": "in_progress"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["resources"]) == 1
        assert body["resources"][0]["id"] == det_id

        # Verify status changed
        entity_resp = client.post(
            "/cs/alerts/entities/alerts/v2",
            headers=headers,
            json={"ids": [det_id]},
        )
        assert entity_resp.json()["resources"][0]["status"] == "in_progress"

    def test_update_detection_with_composite_ids_key(self, client: TestClient) -> None:
        """The endpoint accepts both 'ids' and 'composite_ids' keys."""
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 1},
        )
        det_id = query_resp.json()["resources"][0]

        resp = client.patch(
            "/cs/alerts/entities/alerts/v3",
            headers=headers,
            json={"composite_ids": [det_id], "status": "closed"},
        )
        assert resp.status_code == 200

    def test_update_response_envelope(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        query_resp = client.get(
            "/cs/alerts/queries/alerts/v2",
            headers=headers,
            params={"limit": 1},
        )
        det_id = query_resp.json()["resources"][0]

        resp = client.patch(
            "/cs/alerts/entities/alerts/v3",
            headers=headers,
            json={"ids": [det_id], "status": "true_positive"},
        )
        body = resp.json()
        assert body["meta"]["powered_by"] == "crowdstrike-api"
        assert "trace_id" in body["meta"]
        assert body["errors"] == []
