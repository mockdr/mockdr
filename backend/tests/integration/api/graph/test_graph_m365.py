"""Integration tests for Microsoft Graph M365 service endpoints (Mail, Files, Teams, etc.)."""
from fastapi.testclient import TestClient


class TestGraphMail:
    """Tests for /graph/v1.0/users/{id}/messages and mail folders."""

    def _get_first_user_id(self, client: TestClient, headers: dict) -> str:
        """Helper to get the first seeded user ID."""
        resp = client.get(
            "/graph/v1.0/users",
            params={"$top": 1},
            headers=headers,
        )
        return resp.json()["value"][0]["id"]

    def test_list_user_messages_returns_messages(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id}/messages should return mail messages."""
        user_id = self._get_first_user_id(client, graph_admin_headers)
        resp = client.get(
            f"/graph/v1.0/users/{user_id}/messages",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) >= 1
        msg = body["value"][0]
        assert "subject" in msg
        assert "sender" in msg

    def test_list_user_mail_folders_returns_5(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id}/mailFolders should return 5 folders."""
        user_id = self._get_first_user_id(client, graph_admin_headers)
        resp = client.get(
            f"/graph/v1.0/users/{user_id}/mailFolders",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 5
        folder = body["value"][0]
        assert "displayName" in folder
        assert "totalItemCount" in folder

    def test_send_mail_returns_202(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """POST /v1.0/users/{id}/sendMail should return 202 Accepted."""
        user_id = self._get_first_user_id(client, graph_admin_headers)
        resp = client.post(
            f"/graph/v1.0/users/{user_id}/sendMail",
            json={
                "message": {
                    "subject": "Test Email",
                    "body": {"contentType": "Text", "content": "Hello"},
                    "toRecipients": [
                        {"emailAddress": {"address": "test@acmecorp.onmicrosoft.com"}},
                    ],
                },
            },
            headers=graph_admin_headers,
        )
        assert resp.status_code == 202


class TestGraphFiles:
    """Tests for OneDrive / SharePoint endpoints."""

    def _get_first_user_id(self, client: TestClient, headers: dict) -> str:
        """Helper to get the first seeded user ID."""
        resp = client.get(
            "/graph/v1.0/users",
            params={"$top": 1},
            headers=headers,
        )
        return resp.json()["value"][0]["id"]

    def test_get_user_drive_returns_drive(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id}/drive should return a drive object."""
        user_id = self._get_first_user_id(client, graph_admin_headers)
        resp = client.get(
            f"/graph/v1.0/users/{user_id}/drive",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "id" in body
        assert "driveType" in body
        assert body["driveType"] == "personal"

    def test_list_drive_children_returns_items(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/users/{id}/drive/root/children should return drive items."""
        user_id = self._get_first_user_id(client, graph_admin_headers)
        resp = client.get(
            f"/graph/v1.0/users/{user_id}/drive/root/children",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) >= 1
        item = body["value"][0]
        assert "name" in item

    def test_list_sharepoint_sites_returns_2(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/sites should return 2 SharePoint sites."""
        resp = client.get("/graph/v1.0/sites", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 2
        site = body["value"][0]
        assert "displayName" in site
        assert "webUrl" in site


class TestGraphTeams:
    """Tests for /graph/v1.0/teams."""

    def test_list_teams_returns_4(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 4 teams."""
        resp = client.get("/graph/v1.0/teams", headers=graph_admin_headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 4

    def test_get_team_returns_single(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/teams/{id} should return a single team."""
        list_resp = client.get("/graph/v1.0/teams", headers=graph_admin_headers)
        team_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/teams/{team_id}", headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == team_id
        assert "displayName" in body
        assert "visibility" in body

    def test_list_channels_returns_channels(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/teams/{id}/channels should return channels."""
        list_resp = client.get("/graph/v1.0/teams", headers=graph_admin_headers)
        team_id = list_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/teams/{team_id}/channels",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        # Each team has General + extra channels
        assert len(body["value"]) >= 2
        channel = body["value"][0]
        assert "displayName" in channel

    def test_list_channel_messages_returns_messages(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """GET /v1.0/teams/{id}/channels/{cid}/messages should return messages."""
        teams_resp = client.get("/graph/v1.0/teams", headers=graph_admin_headers)
        team_id = teams_resp.json()["value"][0]["id"]

        channels_resp = client.get(
            f"/graph/v1.0/teams/{team_id}/channels",
            headers=graph_admin_headers,
        )
        channel_id = channels_resp.json()["value"][0]["id"]

        resp = client.get(
            f"/graph/v1.0/teams/{team_id}/channels/{channel_id}/messages",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body


class TestGraphDefenderOffice:
    """Tests for Defender for Office 365 endpoints."""

    def test_list_attack_simulations_returns_3(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 3 attack simulations."""
        resp = client.get(
            "/graph/v1.0/security/attackSimulation/simulations",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 3
        sim = body["value"][0]
        assert "displayName" in sim
        assert "attackTechnique" in sim

    def test_plan1_cannot_access_simulations(
        self, client: TestClient, graph_p1_headers: dict,
    ) -> None:
        """Plan 1 token should receive 403 for attack simulations."""
        resp = client.get(
            "/graph/v1.0/security/attackSimulation/simulations",
            headers=graph_p1_headers,
        )
        assert resp.status_code == 403


class TestGraphServiceHealth:
    """Tests for /graph/v1.0/admin/serviceAnnouncement/healthOverviews."""

    def test_list_service_health_returns_6(
        self, client: TestClient, graph_admin_headers: dict,
    ) -> None:
        """Seed data should contain 6 service health entries."""
        resp = client.get(
            "/graph/v1.0/admin/serviceAnnouncement/healthOverviews",
            headers=graph_admin_headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert len(body["value"]) == 6
        svc = body["value"][0]
        assert "service" in svc
        assert "status" in svc
