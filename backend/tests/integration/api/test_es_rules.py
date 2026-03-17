"""Integration tests for Kibana Detection Engine Rules API.

Verifies CRUD, find with pagination, bulk actions, tags, and prepackaged
status at ``/kibana/api/detection_engine/rules``.
"""
import base64

from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode(),
}

KBN_WRITE_HEADERS = {
    **ES_AUTH,
    "kbn-xsrf": "true",
}


def _get_first_rule_id(client: TestClient) -> str:
    """Return the internal 'id' of the first seeded rule."""
    resp = client.get(
        "/kibana/api/detection_engine/rules/_find",
        headers=ES_AUTH,
        params={"per_page": 1},
    )
    return resp.json()["data"][0]["id"]


class TestFindRules:
    """Tests for GET /kibana/api/detection_engine/rules/_find."""

    def test_find_returns_200(self, client: TestClient) -> None:
        """Find endpoint should return 200 with valid auth."""
        resp = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200

    def test_find_response_has_kibana_pagination(self, client: TestClient) -> None:
        """Response must include page, per_page, total, and data keys."""
        body = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
        ).json()
        assert "page" in body
        assert "per_page" in body
        assert "total" in body
        assert "data" in body
        assert isinstance(body["data"], list)

    def test_find_returns_25_seeded_rules(self, client: TestClient) -> None:
        """Seeder creates 25 rules; total should be 25."""
        body = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 100},
        ).json()
        assert body["total"] == 25
        assert len(body["data"]) == 25

    def test_find_with_per_page_and_page(self, client: TestClient) -> None:
        """Pagination params should control page size and offset."""
        body = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 5, "page": 2},
        ).json()
        assert body["page"] == 2
        assert body["per_page"] == 5
        assert len(body["data"]) == 5

    def test_find_pages_are_disjoint(self, client: TestClient) -> None:
        """Page 1 and page 2 should contain different rules."""
        p1 = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 5, "page": 1},
        ).json()["data"]
        p2 = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 5, "page": 2},
        ).json()["data"]
        ids1 = {r["id"] for r in p1}
        ids2 = {r["id"] for r in p2}
        assert ids1.isdisjoint(ids2)

    def test_find_with_enabled_filter(self, client: TestClient) -> None:
        """Filter for enabled rules should return only enabled rules."""
        body = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"filter": "alert.attributes.enabled: true", "per_page": 100},
        ).json()
        for rule in body["data"]:
            assert rule["enabled"] is True

    def test_rule_has_required_fields(self, client: TestClient) -> None:
        """Each rule must include key detection rule fields."""
        body = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 1},
        ).json()
        rule = body["data"][0]
        required = [
            "id", "rule_id", "name", "description", "type", "query",
            "language", "severity", "risk_score", "enabled", "tags",
            "author", "version", "created_at", "updated_at",
        ]
        for field in required:
            assert field in rule, f"Missing required field: {field}"


class TestGetRule:
    """Tests for GET /kibana/api/detection_engine/rules?id=..."""

    def test_get_rule_by_id(self, client: TestClient) -> None:
        """Getting a rule by its internal ID should return the full rule."""
        rule_id = _get_first_rule_id(client)
        resp = client.get(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            params={"id": rule_id},
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == rule_id

    def test_get_nonexistent_rule_returns_404(self, client: TestClient) -> None:
        """Non-existent rule ID should return 404."""
        resp = client.get(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            params={"id": "nonexistent-rule-id"},
        )
        assert resp.status_code == 404


class TestCreateRule:
    """Tests for POST /kibana/api/detection_engine/rules."""

    def test_create_rule_returns_200(self, client: TestClient) -> None:
        """Creating a rule with valid data should return 200."""
        resp = client.post(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={
                "name": "Test Detection Rule",
                "description": "Integration test rule.",
                "type": "query",
                "query": "process.name: evil.exe",
                "language": "kuery",
                "severity": "high",
                "risk_score": 73,
                "tags": ["test"],
            },
        )
        assert resp.status_code == 200

    def test_create_rule_response_has_id(self, client: TestClient) -> None:
        """Newly created rule should have an assigned id and rule_id."""
        body = client.post(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={
                "name": "ID Check Rule",
                "type": "query",
                "risk_score": 50,
                "severity": "medium",
            },
        ).json()
        assert "id" in body
        assert "rule_id" in body
        assert body["name"] == "ID Check Rule"
        assert body["version"] == 1

    def test_create_rule_without_kbn_xsrf_returns_400(self, client: TestClient) -> None:
        """Missing kbn-xsrf header on a POST should return 400."""
        resp = client.post(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            json={"name": "No XSRF", "type": "query", "risk_score": 50, "severity": "low"},
        )
        assert resp.status_code == 400

    def test_created_rule_appears_in_find(self, client: TestClient) -> None:
        """A created rule should be visible in the _find listing."""
        before = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 200},
        ).json()["total"]

        client.post(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={"name": "Findable Rule", "type": "query", "risk_score": 50, "severity": "low"},
        )

        after = client.get(
            "/kibana/api/detection_engine/rules/_find",
            headers=ES_AUTH,
            params={"per_page": 200},
        ).json()["total"]
        assert after == before + 1


class TestUpdateRule:
    """Tests for PUT /kibana/api/detection_engine/rules."""

    def test_update_rule_name(self, client: TestClient) -> None:
        """Updating a rule's name should persist the change."""
        rule_id = _get_first_rule_id(client)
        resp = client.put(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={"id": rule_id, "name": "Updated Rule Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "Updated Rule Name"

    def test_update_increments_version(self, client: TestClient) -> None:
        """Each update should increment the rule version."""
        rule_id = _get_first_rule_id(client)
        original = client.get(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            params={"id": rule_id},
        ).json()
        original_version = original["version"]

        updated = client.put(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={"id": rule_id, "severity": "critical"},
        ).json()
        assert updated["version"] == original_version + 1

    def test_update_nonexistent_rule_returns_404(self, client: TestClient) -> None:
        """Updating a non-existent rule should return 404."""
        resp = client.put(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={"id": "nonexistent-id", "name": "Ghost"},
        )
        assert resp.status_code == 404

    def test_update_without_id_returns_400(self, client: TestClient) -> None:
        """Update without 'id' in body should return 400."""
        resp = client.put(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            json={"name": "Missing ID"},
        )
        assert resp.status_code == 400


class TestDeleteRule:
    """Tests for DELETE /kibana/api/detection_engine/rules?id=..."""

    def test_delete_rule(self, client: TestClient) -> None:
        """Deleting a rule should return the rule and remove it from the store."""
        rule_id = _get_first_rule_id(client)
        resp = client.delete(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            params={"id": rule_id},
        )
        assert resp.status_code == 200
        assert resp.json()["id"] == rule_id

        # Verify it is gone
        get_resp = client.get(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            params={"id": rule_id},
        )
        assert get_resp.status_code == 404

    def test_delete_nonexistent_rule_returns_404(self, client: TestClient) -> None:
        """Deleting a non-existent rule should return 404."""
        resp = client.delete(
            "/kibana/api/detection_engine/rules",
            headers=KBN_WRITE_HEADERS,
            params={"id": "nonexistent-id"},
        )
        assert resp.status_code == 404


class TestBulkAction:
    """Tests for POST /kibana/api/detection_engine/rules/_bulk_action."""

    def test_bulk_disable(self, client: TestClient) -> None:
        """Bulk disable should set enabled=False on targeted rules."""
        rule_id = _get_first_rule_id(client)
        resp = client.post(
            "/kibana/api/detection_engine/rules/_bulk_action",
            headers=KBN_WRITE_HEADERS,
            json={"action": "disable", "ids": [rule_id]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["rules_count"] == 1

        # Verify it is disabled
        rule = client.get(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            params={"id": rule_id},
        ).json()
        assert rule["enabled"] is False

    def test_bulk_enable(self, client: TestClient) -> None:
        """Bulk enable should set enabled=True on targeted rules."""
        rule_id = _get_first_rule_id(client)
        # First disable it
        client.post(
            "/kibana/api/detection_engine/rules/_bulk_action",
            headers=KBN_WRITE_HEADERS,
            json={"action": "disable", "ids": [rule_id]},
        )
        # Then enable it
        resp = client.post(
            "/kibana/api/detection_engine/rules/_bulk_action",
            headers=KBN_WRITE_HEADERS,
            json={"action": "enable", "ids": [rule_id]},
        )
        assert resp.status_code == 200
        assert resp.json()["success"] is True

        rule = client.get(
            "/kibana/api/detection_engine/rules",
            headers=ES_AUTH,
            params={"id": rule_id},
        ).json()
        assert rule["enabled"] is True

    def test_bulk_action_without_action_returns_400(self, client: TestClient) -> None:
        """Missing 'action' field should return 400."""
        resp = client.post(
            "/kibana/api/detection_engine/rules/_bulk_action",
            headers=KBN_WRITE_HEADERS,
            json={"ids": ["some-id"]},
        )
        assert resp.status_code == 400


class TestRuleTags:
    """Tests for GET /kibana/api/detection_engine/rules/tags."""

    def test_get_tags_returns_list(self, client: TestClient) -> None:
        """Tags endpoint should return a sorted list of unique strings."""
        resp = client.get(
            "/kibana/api/detection_engine/rules/tags",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200
        tags = resp.json()
        assert isinstance(tags, list)
        assert len(tags) > 0
        # Should be sorted
        assert tags == sorted(tags)

    def test_tags_contain_known_values(self, client: TestClient) -> None:
        """Tags should include at least 'Elastic' — present in all seeded rules."""
        tags = client.get(
            "/kibana/api/detection_engine/rules/tags",
            headers=ES_AUTH,
        ).json()
        assert "Elastic" in tags


class TestPrepackagedStatus:
    """Tests for GET /kibana/api/detection_engine/rules/prepackaged/_status."""

    def test_prepackaged_status_returns_200(self, client: TestClient) -> None:
        """Prepackaged status endpoint should return 200."""
        resp = client.get(
            "/kibana/api/detection_engine/rules/prepackaged/_status",
            headers=ES_AUTH,
        )
        assert resp.status_code == 200

    def test_prepackaged_status_has_correct_fields(self, client: TestClient) -> None:
        """Response must include rules_custom_installed and static zero counts."""
        body = client.get(
            "/kibana/api/detection_engine/rules/prepackaged/_status",
            headers=ES_AUTH,
        ).json()
        assert body["rules_custom_installed"] == 25
        assert body["rules_installed"] == 0
        assert body["rules_not_installed"] == 0
        assert body["timelines_installed"] == 0
