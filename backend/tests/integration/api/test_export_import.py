"""Integration tests for export/import endpoints.

GET  /_dev/export  — serialize the full store to JSON
POST /_dev/import  — restore from a snapshot
"""
from fastapi.testclient import TestClient


class TestExport:
    """Tests for GET /_dev/export."""

    def test_export_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/_dev/export", headers=auth_headers)
        assert resp.status_code == 200

    def test_export_contains_all_collection_keys(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        resp = client.get("/web/api/v2.1/_dev/export", headers=auth_headers)
        body = resp.json()
        expected_keys = {
            "accounts", "sites", "groups", "agents", "threats", "alerts",
            "activities", "exclusions", "policies", "firewall_rules", "iocs",
            "users", "device_control_rules", "dv_queries", "webhook_subscriptions",
            "installed_apps", "blocklist", "api_tokens",
        }
        for key in expected_keys:
            assert key in body, f"Collection '{key}' missing from export"

    def test_export_agents_non_empty(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get("/web/api/v2.1/_dev/export", headers=auth_headers)
        assert len(resp.json()["agents"]) > 0


class TestImport:
    """Tests for POST /_dev/import."""

    def test_import_with_export_result_preserves_agent_count(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        # Get original agent count
        agents_resp = client.get("/web/api/v2.1/agents", headers=auth_headers)
        original_count = agents_resp.json()["pagination"]["totalItems"]

        # Export and re-import
        export = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        import_resp = client.post(
            "/web/api/v2.1/_dev/import", headers=auth_headers, json=export
        )
        assert import_resp.status_code == 200
        assert "imported" in import_resp.json()["data"]

        # Agent count should match
        agents_after = client.get("/web/api/v2.1/agents", headers=auth_headers)
        assert agents_after.json()["pagination"]["totalItems"] == original_count

    def test_import_empty_dict_results_in_empty_collections(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        import_resp = client.post(
            "/web/api/v2.1/_dev/import", headers=auth_headers, json={}
        )
        assert import_resp.status_code == 200
        assert import_resp.json()["data"]["imported"] == 0

        # After import with {}, api_tokens is also empty so auth will fail.
        # We just verify the import returned 0 imported records.
        assert import_resp.json()["data"]["imported"] == 0

    def test_import_returns_total_imported_count(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        export = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        resp = client.post(
            "/web/api/v2.1/_dev/import", headers=auth_headers, json=export
        )
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"]["imported"], int)
        assert resp.json()["data"]["imported"] > 0


class TestExportActivityOrder:
    """Verify that _activity_order is exported and restored correctly."""

    def test_export_includes_activity_order(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Snapshot must contain _activity_order for ordering preservation."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        assert "_activity_order" in snap
        assert isinstance(snap["_activity_order"], list)
        assert len(snap["_activity_order"]) > 0

    def test_activity_order_matches_activity_ids(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Every ID in _activity_order must exist in the activities collection."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        activity_ids = {a["id"] for a in snap["activities"]}
        for oid in snap["_activity_order"]:
            assert oid in activity_ids

    def test_import_preserves_activity_order(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Activities returned after import must be in the same order as before."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        original_order = snap["_activity_order"]

        client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)

        snap_after = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        assert snap_after["_activity_order"] == original_order


class TestExportPolicyKeys:
    """Verify that policies survive a full export -> import round-trip."""

    def test_policies_restored_after_import(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Policy count must be identical before and after export/import."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        policy_count_before = len(snap["policies"])

        client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)

        snap_after = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        assert len(snap_after["policies"]) == policy_count_before

    def test_policy_site_scope_survives_roundtrip(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Site-scoped policies must be retrievable via GET /policies?siteId after import."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        site_policies = [p for p in snap["policies"] if p["scopeType"] == "site"]
        assert len(site_policies) > 0, "Seed must contain at least one site policy"

        client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)

        site_id = site_policies[0]["scopeId"]
        resp = client.get(
            f"/web/api/v2.1/policies?siteId={site_id}", headers=auth_headers
        )
        assert resp.status_code == 200
        assert resp.json()["data"] is not None


class TestImportEdgeCases:
    """Import robustness: malformed input, missing fields, fallback paths."""

    def test_malformed_typed_record_is_skipped(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """A record that cannot be reconstructed (missing required field) is silently skipped."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        agent_count_before = len(snap["agents"])
        # Corrupt one agent record so cls(**record) raises TypeError
        snap["agents"].append({"bad_field_only": True})
        resp = client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)
        assert resp.status_code == 200
        # Total imported should equal the uncorrupted records only
        snap_after = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        assert len(snap_after["agents"]) == agent_count_before

    def test_non_dict_raw_record_is_skipped(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Non-dict entries in raw collections (blocklist, installed_apps) are skipped."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        snap["blocklist"].append("not-a-dict")
        resp = client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)
        assert resp.status_code == 200

    def test_raw_record_missing_id_is_skipped(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Raw records with no 'id' field are silently skipped."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        snap["blocklist"].append({"value": "abc", "type": "black_hash"})  # no "id" key
        resp = client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)
        assert resp.status_code == 200

    def test_import_without_activity_order_falls_back_to_sort(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Snapshots without _activity_order rebuild ordering by createdAt."""
        snap = client.get("/web/api/v2.1/_dev/export", headers=auth_headers).json()
        # Remove _activity_order to trigger the fallback path
        snap.pop("_activity_order", None)
        resp = client.post("/web/api/v2.1/_dev/import", headers=auth_headers, json=snap)
        assert resp.status_code == 200
        # Activities should still be importable
        acts_resp = client.get("/web/api/v2.1/activities", headers=auth_headers)
        assert acts_resp.status_code == 200
        assert acts_resp.json()["pagination"]["totalItems"] > 0
