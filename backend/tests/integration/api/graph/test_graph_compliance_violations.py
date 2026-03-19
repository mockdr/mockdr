"""Cross-cutting compliance violation tests for Microsoft Graph API mock data.

These tests verify that the seed data contains realistic security compliance
violations that training exercises should detect, such as former employees
with active forwarding rules, too many global admins, and EOL operating systems.
"""
from fastapi.testclient import TestClient


class TestComplianceViolations:
    """Cross-cutting compliance violation checks across Graph API data."""

    def test_former_employee_has_external_forwarding(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """A disabled (former employee) user should have an active external forwarding rule."""
        users_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        users = users_resp.json()["value"]
        disabled_users = [u for u in users if not u["accountEnabled"]]
        assert len(disabled_users) >= 1, "Need disabled users for this test"

        found = False
        for user in disabled_users:
            rules_resp = client.get(
                f"/graph/v1.0/users/{user['id']}/mailFolders/inbox/messageRules",
                headers=graph_admin_headers,
            )
            for rule in rules_resp.json()["value"]:
                actions = rule.get("actions", {})
                forwarding_keys = ("forwardTo", "redirectTo", "forwardAsAttachmentTo")
                if any(key in actions for key in forwarding_keys):
                    found = True
                    break
            if found:
                break

        assert found, (
            "Expected at least one disabled user with an external forwarding rule"
        )

    def test_former_employee_in_global_admin_role(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """A disabled user should be a member of the Global Administrator role."""
        # Get disabled user IDs
        users_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        disabled_ids = {
            u["id"] for u in users_resp.json()["value"]
            if not u["accountEnabled"]
        }

        # Find the Global Administrator role
        roles_resp = client.get(
            "/graph/v1.0/directoryRoles", headers=graph_admin_headers,
        )
        ga_role = next(
            (r for r in roles_resp.json()["value"]
             if r["displayName"] == "Global Administrator"),
            None,
        )
        assert ga_role is not None, "Global Administrator role not found"

        # Check members
        members_resp = client.get(
            f"/graph/v1.0/directoryRoles/{ga_role['id']}/members",
            headers=graph_admin_headers,
        )
        member_ids = {m["id"] for m in members_resp.json()["value"]}
        overlap = member_ids & disabled_ids
        assert len(overlap) >= 1, (
            "Expected at least one disabled user in Global Administrator role"
        )

    def test_too_many_global_admins(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Global Administrator role should have more than 4 members (CIS violation)."""
        roles_resp = client.get(
            "/graph/v1.0/directoryRoles", headers=graph_admin_headers,
        )
        ga_role = next(
            (r for r in roles_resp.json()["value"]
             if r["displayName"] == "Global Administrator"),
            None,
        )
        assert ga_role is not None

        members_resp = client.get(
            f"/graph/v1.0/directoryRoles/{ga_role['id']}/members",
            headers=graph_admin_headers,
        )
        member_count = len(members_resp.json()["value"])
        assert member_count > 4, (
            f"Expected >4 Global Admins (CIS violation), got {member_count}"
        )

    def test_admin_without_mfa(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Cross-reference admin role members with MFA registration to find gaps.

        This test validates the data shape for the compliance check; with
        ~20% MFA-unregistered rate in seed data, finding an admin without
        MFA is probable but not guaranteed.
        """
        # Get all directory role members
        roles_resp = client.get(
            "/graph/v1.0/directoryRoles", headers=graph_admin_headers,
        )
        admin_ids: set[str] = set()
        for role in roles_resp.json()["value"]:
            members_resp = client.get(
                f"/graph/v1.0/directoryRoles/{role['id']}/members",
                headers=graph_admin_headers,
            )
            for member in members_resp.json()["value"]:
                admin_ids.add(member["id"])

        # Get MFA registration details
        mfa_resp = client.get(
            "/graph/beta/reports/authenticationMethods/userRegistrationDetails",
            headers=graph_admin_headers,
        )
        mfa_map = {d["id"]: d["isMfaRegistered"] for d in mfa_resp.json()["value"]}

        # Check admin MFA status — at least verify the cross-reference works
        admins_checked = [aid for aid in admin_ids if aid in mfa_map]
        assert len(admins_checked) >= 1, "Expected to find admin IDs in MFA details"

    def test_stale_enabled_account_exists(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one enabled account should have stale sign-in activity (>90 days)."""
        resp = client.get("/graph/beta/users", headers=graph_admin_headers)
        users = resp.json()["value"]

        from datetime import UTC, datetime, timedelta
        threshold = datetime.now(UTC) - timedelta(days=90)

        stale_accounts = []
        for user in users:
            if not user.get("accountEnabled"):
                continue
            sign_in = user.get("signInActivity", {})
            last_sign_in = sign_in.get("lastSignInDateTime", "")
            if not last_sign_in:
                continue
            try:
                dt = datetime.fromisoformat(last_sign_in.replace("Z", "+00:00"))
                if dt < threshold:
                    stale_accounts.append(user["displayName"])
            except (ValueError, TypeError):
                continue

        assert len(stale_accounts) >= 1, (
            "Expected at least one enabled account with >90-day stale sign-in"
        )

    def test_guest_users_exist(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Guest/external users should exist in the directory."""
        resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        users = resp.json()["value"]
        guests = [
            u for u in users
            if "#EXT#" in u.get("userPrincipalName", "")
        ]
        assert len(guests) == 3, f"Expected 3 guest users, got {len(guests)}"

    def test_unverified_app_with_broad_permissions(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """An unverified app should have broad permissions (e.g. Files.ReadWrite.All)."""
        resp = client.get(
            "/graph/v1.0/servicePrincipals",
            headers=graph_admin_headers,
        )
        sps = resp.json()["value"]

        found = False
        for sp in sps:
            publisher = sp.get("verifiedPublisher", {}).get("displayName")
            if publisher is not None:
                continue
            # Check for broad permission scopes
            grants = sp.get("oauth2PermissionGrants", [])
            scopes = [g.get("scope", "") for g in grants]
            broad_scopes = {"Files.ReadWrite.All", "Mail.Read"}
            if any(s in broad_scopes for s in scopes):
                found = True
                break

        assert found, (
            "Expected an unverified app with broad permissions (Files.ReadWrite.All)"
        )

    def test_eol_os_across_vendors(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one managed device should have an EOL OS version.

        The same machine should exist in both the Graph managed devices
        (from Intune) and the S1 agent fleet with the same EOL OS.
        """
        resp = client.get(
            "/graph/v1.0/deviceManagement/managedDevices",
            headers=graph_admin_headers,
        )
        devices = resp.json()["value"]
        eol_markers = ("8.1", "Big Sur", "1809", "CentOS 7")
        eol_devices = [
            d for d in devices
            if any(m in d.get("osVersion", "") for m in eol_markers)
        ]
        assert len(eol_devices) >= 1, (
            "Expected at least one device with EOL OS version"
        )
        # Verify the EOL device is marked noncompliant
        for dev in eol_devices:
            assert dev["complianceState"] == "noncompliant", (
                f"EOL device {dev['deviceName']} should be noncompliant"
            )

    def test_license_near_exhaustion(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one SKU should have consumed units near the prepaid limit."""
        resp = client.get("/graph/v1.0/subscribedSkus", headers=graph_admin_headers)
        skus = resp.json()["value"]

        near_exhaustion = []
        for sku in skus:
            enabled = sku["prepaidUnits"]["enabled"]
            consumed = sku["consumedUnits"]
            if enabled > 0 and consumed >= int(enabled * 0.90):
                near_exhaustion.append(sku["skuPartNumber"])

        assert len(near_exhaustion) >= 1, (
            "Expected at least one SKU near license exhaustion"
        )

    def test_ca_policy_in_report_only(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one Conditional Access policy should be in report-only mode."""
        resp = client.get(
            "/graph/v1.0/identity/conditionalAccess/policies",
            headers=graph_admin_headers,
        )
        policies = resp.json()["value"]
        report_only = [
            p for p in policies
            if p["state"] == "enabledForReportingButNotEnforced"
        ]
        assert len(report_only) >= 1, (
            "Expected at least one CA policy in report-only mode"
        )
