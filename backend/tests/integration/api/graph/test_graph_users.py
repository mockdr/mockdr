"""Integration tests for Microsoft Graph Users endpoints."""
from fastapi.testclient import TestClient


class TestGraphUsers:
    """Tests for GET /graph/v1.0/users and related sub-resources."""

    def test_list_users_returns_odata_envelope(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users should return an OData envelope with @odata.context and value."""
        resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_list_users_returns_expected_count(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 28 users (25 base + 3 guest)."""
        resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        assert resp.status_code == 200
        assert len(resp.json()["value"]) == 28

    def test_list_users_with_select_returns_only_selected_fields(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$select=id,displayName should return only those fields per user."""
        resp = client.get(
            "/graph/v1.0/users",
            params={"$select": "id,displayName"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        for user in resp.json()["value"]:
            assert "id" in user
            assert "displayName" in user
            # Fields not selected must be absent
            assert "mail" not in user
            assert "department" not in user

    def test_list_users_with_top_limits_results(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$top=5 should return at most 5 users."""
        resp = client.get(
            "/graph/v1.0/users",
            params={"$top": 5},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["value"]) == 5

    def test_list_users_with_filter_by_department(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$filter=department eq 'IT' should return only IT users."""
        resp = client.get(
            "/graph/v1.0/users",
            params={"$filter": "department eq 'IT'"},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        for user in body["value"]:
            assert user["department"] == "IT"

    def test_list_users_with_search_by_display_name(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$search should filter users by displayName substring match."""
        # First get all users to find a name to search for
        all_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        first_user = all_resp.json()["value"][0]
        # Use the first name as a search term
        search_term = first_user["displayName"].split()[0]

        resp = client.get(
            "/graph/v1.0/users",
            params={"$search": f'"{search_term}"'},
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        assert len(resp.json()["value"]) >= 1

    def test_list_users_beta_returns_sign_in_activity(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /beta/users should return users with signInActivity."""
        resp = client.get("/graph/beta/users", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["value"]) == 28
        # All seeded users have signInActivity
        for user in body["value"]:
            assert "signInActivity" in user

    def test_get_user_returns_single_user(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id} should return a single user dict (not wrapped in value)."""
        list_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        user_id = list_resp.json()["value"][0]["id"]

        resp = client.get(f"/graph/v1.0/users/{user_id}", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == user_id
        assert "displayName" in body
        assert "userPrincipalName" in body

    def test_get_user_not_found_returns_404(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{nonexistent} should return 404."""
        resp = client.get(
            "/graph/v1.0/users/00000000-0000-0000-0000-000000000000",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 404

    def test_get_user_member_of_returns_groups(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id}/memberOf should return an OData list."""
        list_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        user_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/users/{user_id}/memberOf",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_get_user_mail_rules_returns_rules(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id}/mailFolders/inbox/messageRules should return OData list."""
        # Get users and find one that has mail rules
        users_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        users = users_resp.json()["value"]

        found_rules = False
        for user in users:
            resp = client.get(
                f"/graph/v1.0/users/{user['id']}/mailFolders/inbox/messageRules",
                headers=graph_admin_headers,
            )
            assert resp.status_code == 200
            body = resp.json()
            assert "@odata.context" in body
            assert "value" in body
            if len(body["value"]) > 0:
                found_rules = True
                rule = body["value"][0]
                assert "displayName" in rule
                assert "actions" in rule
                break
        assert found_rules, "Expected at least one user to have mail rules"

    def test_mail_rules_contain_forward_to_addresses(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """At least one mail rule should contain a forwardTo, redirectTo, or forwardAsAttachmentTo action."""
        users_resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        users = users_resp.json()["value"]

        forward_found = False
        for user in users:
            resp = client.get(
                f"/graph/v1.0/users/{user['id']}/mailFolders/inbox/messageRules",
                headers=graph_admin_headers,
            )
            for rule in resp.json()["value"]:
                actions = rule.get("actions", {})
                if any(
                    key in actions
                    for key in ("forwardTo", "redirectTo", "forwardAsAttachmentTo")
                ):
                    forward_found = True
                    break
            if forward_found:
                break

        assert forward_found, "Expected at least one forwarding rule in seed data"

    def test_disabled_users_exist_in_seed_data(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should include at least one disabled (accountEnabled=false) user."""
        resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        users = resp.json()["value"]
        disabled = [u for u in users if not u["accountEnabled"]]
        assert len(disabled) >= 1, "Expected at least one disabled user"

    def test_guest_users_exist_with_ext_upn(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should include 3 guest users with #EXT# in UPN."""
        resp = client.get("/graph/v1.0/users", headers=graph_admin_headers)
        users = resp.json()["value"]
        guests = [u for u in users if "#EXT#" in u.get("userPrincipalName", "")]
        assert len(guests) == 3

    def test_count_with_consistency_level_header(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """$count=true with ConsistencyLevel=eventual should include @odata.count."""
        headers = {**graph_admin_headers, "ConsistencyLevel": "eventual"}
        resp = client.get(
            "/graph/v1.0/users",
            params={"$count": "true"},
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.count" in body
        assert body["@odata.count"] == 28
