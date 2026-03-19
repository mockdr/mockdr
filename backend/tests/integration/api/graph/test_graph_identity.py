"""Integration tests for Microsoft Graph Identity and Directory endpoints."""
from fastapi.testclient import TestClient


class TestGraphDirectoryRoles:
    """Tests for /graph/v1.0/directoryRoles."""

    def test_list_directory_roles_returns_8(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 8 directory roles."""
        resp = client.get("/graph/v1.0/directoryRoles", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 8
        role = body["value"][0]
        assert "displayName" in role
        assert "id" in role

    def test_get_role_members_returns_users(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/directoryRoles/{id}/members should return user members."""
        roles_resp = client.get(
            "/graph/v1.0/directoryRoles", headers=graph_admin_headers,
        )
        role_id = roles_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/directoryRoles/{role_id}/members",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) >= 1

    def test_disabled_user_in_admin_role(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """A disabled user should exist as a member of a privileged directory role."""
        # Get all users and find disabled ones
        users_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        disabled_ids = {
            u["id"] for u in users_resp.json()["value"]
            if not u["accountEnabled"]
        }

        # Get all directory roles and check their members
        roles_resp = client.get(
            "/graph/v1.0/directoryRoles", headers=graph_admin_headers,
        )
        roles = roles_resp.json()["value"]

        found = False
        for role in roles:
            members_resp = client.get(
                f"/graph/v1.0/directoryRoles/{role['id']}/members",
                headers=graph_admin_headers,
            )
            member_ids = {m["id"] for m in members_resp.json()["value"]}
            if member_ids & disabled_ids:
                found = True
                break

        assert found, "Expected at least one disabled user in a privileged role"


class TestGraphConditionalAccess:
    """Tests for /graph/v1.0/identity/conditionalAccess/policies."""

    def test_list_ca_policies_returns_6(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 6 Conditional Access policies."""
        resp = client.get(
            "/graph/v1.0/identity/conditionalAccess/policies",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 6

    def test_get_ca_policy_returns_single(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/identity/conditionalAccess/policies/{id} should return a single policy."""
        list_resp = client.get(
            "/graph/v1.0/identity/conditionalAccess/policies",
            headers=graph_admin_headers,
        )
        policy_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/identity/conditionalAccess/policies/{policy_id}",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == policy_id
        assert "displayName" in body
        assert "state" in body

    def test_report_only_policy_exists(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one CA policy should be in report-only mode."""
        resp = client.get(
            "/graph/v1.0/identity/conditionalAccess/policies",
            headers=graph_admin_headers,
        )
        policies = resp.json()["value"]
        report_only = [
            p for p in policies
            if p["state"] == "enabledForReportingButNotEnforced"
        ]
        assert len(report_only) >= 1


class TestGraphNamedLocations:
    """Tests for /graph/v1.0/identity/conditionalAccess/namedLocations."""

    def test_list_named_locations_returns_3(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 3 named locations."""
        resp = client.get(
            "/graph/v1.0/identity/conditionalAccess/namedLocations",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 3


class TestGraphAdminUnits:
    """Tests for /graph/v1.0/directory/administrativeUnits."""

    def test_list_admin_units_returns_2(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 2 administrative units."""
        resp = client.get(
            "/graph/v1.0/directory/administrativeUnits",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 2


class TestGraphServicePrincipals:
    """Tests for /graph/v1.0/servicePrincipals."""

    def test_list_service_principals_returns_8(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 8 service principals."""
        resp = client.get(
            "/graph/v1.0/servicePrincipals",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 8

    def test_unverified_apps_exist(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one service principal should have no verified publisher."""
        resp = client.get(
            "/graph/v1.0/servicePrincipals",
            headers=graph_admin_headers,
        )
        sps = resp.json()["value"]
        unverified = [
            sp for sp in sps
            if sp.get("verifiedPublisher", {}).get("displayName") is None
        ]
        assert len(unverified) >= 1, "Expected at least one unverified service principal"


class TestGraphApplications:
    """Tests for /graph/v1.0/applications."""

    def test_list_applications_returns_5(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 5 application registrations."""
        resp = client.get("/graph/v1.0/applications", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 5
        app = body["value"][0]
        assert "displayName" in app
        assert "appId" in app


class TestGraphSubscribedSkus:
    """Tests for /graph/v1.0/subscribedSkus."""

    def test_list_skus_returns_5(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 5 subscribed SKUs."""
        resp = client.get("/graph/v1.0/subscribedSkus", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 5
        sku = body["value"][0]
        assert "skuPartNumber" in sku
        assert "consumedUnits" in sku
        assert "prepaidUnits" in sku

    def test_intune_license_near_exhaustion(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """The Intune SKU should have consumed units near the prepaid limit."""
        resp = client.get("/graph/v1.0/subscribedSkus", headers=graph_admin_headers)
        skus = resp.json()["value"]
        intune_skus = [s for s in skus if s["skuPartNumber"] == "INTUNE_A"]
        assert len(intune_skus) == 1
        intune = intune_skus[0]
        enabled = intune["prepaidUnits"]["enabled"]
        consumed = intune["consumedUnits"]
        # Near exhaustion: consumed >= 90% of enabled
        assert consumed >= int(enabled * 0.9), (
            f"Expected Intune near exhaustion: {consumed}/{enabled}"
        )
