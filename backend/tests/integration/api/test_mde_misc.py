"""Integration tests for miscellaneous MDE endpoints.

Covers machine actions (listing), investigations, advanced hunting,
software, vulnerabilities, file/domain/IP info, and user lookups.
"""
from fastapi.testclient import TestClient


def _mde_auth(client: TestClient) -> dict[str, str]:
    """Authenticate and return MDE Bearer headers."""
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


# ---------------------------------------------------------------------------
# Machine Actions
# ---------------------------------------------------------------------------


class TestMachineActionsListing:
    """Tests for GET /mde/api/machineactions."""

    def test_list_machine_actions_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machineactions", headers=headers)
        assert resp.status_code == 200

    def test_odata_response_format(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machineactions", headers=headers)
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
        assert isinstance(body["value"], list)

    def test_get_machine_action_by_id(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/machineactions", headers=headers, params={"$top": 1})
        actions = list_resp.json()["value"]
        if not actions:
            return  # No seeded actions; skip
        action_id = actions[0]["actionId"]
        resp = client.get(f"/mde/api/machineactions/{action_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["actionId"] == action_id

    def test_get_package_uri(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/machineactions", headers=headers, params={"$top": 1})
        actions = list_resp.json()["value"]
        if not actions:
            return
        action_id = actions[0]["actionId"]
        resp = client.get(
            f"/mde/api/machineactions/{action_id}/getPackageUri",
            headers=headers,
        )
        assert resp.status_code == 200

    def test_nonexistent_action_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/machineactions/nonexistent-id", headers=headers)
        assert resp.status_code == 404

    def test_action_created_by_isolate_appears_in_listing(self, client: TestClient) -> None:
        """Machine action created via isolate should appear in machineactions listing."""
        headers = _mde_auth(client)
        # Isolate a machine to create an action
        machines_resp = client.get("/mde/api/machines", headers=headers, params={"$top": 1})
        machine_id = machines_resp.json()["value"][0]["machineId"]
        isolate_resp = client.post(
            f"/mde/api/machines/{machine_id}/isolate",
            headers=headers,
            json={"Comment": "Test isolation", "IsolationType": "Full"},
        )
        action_id = isolate_resp.json()["actionId"]

        # Verify the action appears in the listing
        resp = client.get(f"/mde/api/machineactions/{action_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["type"] == "Isolate"


# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------


class TestInvestigations:
    """Tests for /mde/api/investigations endpoints."""

    def test_list_investigations_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/investigations", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_investigation_by_id(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/investigations", headers=headers, params={"$top": 1})
        investigations = list_resp.json()["value"]
        if not investigations:
            return
        inv_id = investigations[0]["investigationId"]
        resp = client.get(f"/mde/api/investigations/{inv_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["investigationId"] == inv_id

    def test_collect_investigation(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/investigations", headers=headers, params={"$top": 1})
        investigations = list_resp.json()["value"]
        if not investigations:
            return
        inv_id = investigations[0]["investigationId"]
        resp = client.post(f"/mde/api/investigations/{inv_id}/collect", headers=headers)
        assert resp.status_code == 200

    def test_nonexistent_investigation_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/investigations/nonexistent-id", headers=headers)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Advanced Hunting
# ---------------------------------------------------------------------------


class TestAdvancedHunting:
    """Tests for POST /mde/api/advancedqueries/run."""

    def test_run_advanced_query(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.post(
            "/mde/api/advancedqueries/run",
            headers=headers,
            json={"Query": "DeviceInfo | take 10"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "Results" in body or "results" in body or "Schema" in body or "Stats" in body


# ---------------------------------------------------------------------------
# Software
# ---------------------------------------------------------------------------


class TestSoftware:
    """Tests for /mde/api/software endpoints."""

    def test_list_software_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/software", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_software_by_id(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/software", headers=headers, params={"$top": 1})
        software_list = list_resp.json()["value"]
        if not software_list:
            return
        sw_id = software_list[0]["softwareId"]
        resp = client.get(f"/mde/api/software/{sw_id}", headers=headers)
        assert resp.status_code == 200

    def test_get_software_machine_references(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/software", headers=headers, params={"$top": 1})
        software_list = list_resp.json()["value"]
        if not software_list:
            return
        sw_id = software_list[0]["softwareId"]
        resp = client.get(f"/mde/api/software/{sw_id}/machineReferences", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_nonexistent_software_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/software/nonexistent-id", headers=headers)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


class TestVulnerabilities:
    """Tests for /mde/api/vulnerabilities endpoints."""

    def test_list_vulnerabilities_returns_200(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/vulnerabilities", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_vulnerability_by_id(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/vulnerabilities", headers=headers, params={"$top": 1})
        vulns = list_resp.json()["value"]
        if not vulns:
            return
        vuln_id = vulns[0]["vulnerabilityId"]
        resp = client.get(f"/mde/api/vulnerabilities/{vuln_id}", headers=headers)
        assert resp.status_code == 200

    def test_get_vulnerability_machine_references(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        list_resp = client.get("/mde/api/vulnerabilities", headers=headers, params={"$top": 1})
        vulns = list_resp.json()["value"]
        if not vulns:
            return
        vuln_id = vulns[0]["vulnerabilityId"]
        resp = client.get(
            f"/mde/api/vulnerabilities/{vuln_id}/machineReferences",
            headers=headers,
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_nonexistent_vulnerability_returns_404(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/vulnerabilities/nonexistent-id", headers=headers)
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# File Info
# ---------------------------------------------------------------------------


class TestFileInfo:
    """Tests for /mde/api/files endpoints."""

    def test_get_file_info(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        # Use a dummy hash — the mock should return synthetic data
        resp = client.get(
            "/mde/api/files/da39a3ee5e6b4b0d3255bfef95601890afd80709",
            headers=headers,
        )
        assert resp.status_code == 200

    def test_get_file_stats(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get(
            "/mde/api/files/da39a3ee5e6b4b0d3255bfef95601890afd80709/stats",
            headers=headers,
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Domain Info
# ---------------------------------------------------------------------------


class TestDomainInfo:
    """Tests for /mde/api/domains endpoints."""

    def test_get_domain_info(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/domains/example.com", headers=headers)
        assert resp.status_code == 200

    def test_get_domain_stats(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/domains/example.com/stats", headers=headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# IP Info
# ---------------------------------------------------------------------------


class TestIpInfo:
    """Tests for /mde/api/ips endpoints."""

    def test_get_ip_info(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/ips/10.0.0.1", headers=headers)
        assert resp.status_code == 200

    def test_get_ip_stats(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/ips/10.0.0.1/stats", headers=headers)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


class TestUsers:
    """Tests for /mde/api/users endpoints."""

    def test_get_user_machines(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        # Get a logged-on user from a machine
        machines_resp = client.get("/mde/api/machines", headers=headers, params={"$top": 1})
        machine = machines_resp.json()["value"][0]
        logon_users = machine.get("loggedOnUsers", [])
        if not logon_users:
            # Try getting logon users via sub-resource
            lu_resp = client.get(
                f"/mde/api/machines/{machine['machineId']}/logonusers",
                headers=headers,
            )
            logon_users = lu_resp.json().get("value", [])

        if logon_users:
            user_id = logon_users[0].get("accountName", logon_users[0].get("id", "testuser"))
        else:
            user_id = "testuser"

        resp = client.get(f"/mde/api/users/{user_id}/machines", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body

    def test_get_user_alerts(self, client: TestClient) -> None:
        headers = _mde_auth(client)
        resp = client.get("/mde/api/users/testuser/alerts", headers=headers)
        assert resp.status_code == 200
        body = resp.json()
        assert "@odata.context" in body
        assert "value" in body
