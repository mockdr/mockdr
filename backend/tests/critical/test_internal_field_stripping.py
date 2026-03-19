"""Critical-path tests: internal field stripping across all domain resources.

These tests verify the security contract that internal mock-only fields are
NEVER exposed through any API endpoint.  Failures here indicate a data
leakage regression and must block CI immediately.

Coverage gate for this module: 95% (see TESTING.md §2).
"""
import pytest
from fastapi.testclient import TestClient

from utils.internal_fields import (
    AGENT_INTERNAL_FIELDS,
    EXCLUSION_INTERNAL_FIELDS,
    FIREWALL_INTERNAL_FIELDS,
    GROUP_INTERNAL_FIELDS,
    SITE_INTERNAL_FIELDS,
    USER_INTERNAL_FIELDS,
)

# ── Agent field stripping ─────────────────────────────────────────────────────

@pytest.mark.critical
class TestAgentInternalFieldStripping:
    """AGENT_INTERNAL_FIELDS must never appear in any agent API response."""

    def test_list_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agents = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"]
        assert agents, "Seed must produce at least one agent"
        for agent in agents:
            for field in AGENT_INTERNAL_FIELDS:
                assert field not in agent, (
                    f"CRITICAL: agent internal field '{field}' leaked in list response"
                )

    def test_single_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        agent_id = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]["id"]
        agent = client.get(f"/web/api/v2.1/agents/{agent_id}", headers=auth_headers).json()["data"]
        for field in AGENT_INTERNAL_FIELDS:
            assert field not in agent, (
                f"CRITICAL: agent internal field '{field}' leaked in single response"
            )

    def test_passphrase_only_on_dedicated_endpoint(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """passphrase is available at /agents/{id}/passphrase but not in the agent body."""
        agent_id = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]["id"]
        agent = client.get(f"/web/api/v2.1/agents/{agent_id}", headers=auth_headers).json()["data"]
        assert "passphrase" not in agent

        passphrase_resp = client.get(
            f"/web/api/v2.1/agents/{agent_id}/passphrase", headers=auth_headers
        )
        assert passphrase_resp.status_code == 200
        assert "passphrase" in passphrase_resp.json()["data"]

    def test_infected_public_field_is_present(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """'infected' (public) must be present; 'isInfected' (internal) must not."""
        agent = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]
        assert "infected" in agent, "Public field 'infected' missing from agent"
        assert "isInfected" not in agent, "Internal field 'isInfected' leaked"

    def test_last_ip_to_mgmt_present_local_ip_absent(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """'lastIpToMgmt' (public) must be present; 'localIp' (internal alias) must not."""
        agent = client.get("/web/api/v2.1/agents", headers=auth_headers).json()["data"][0]
        assert "lastIpToMgmt" in agent, "Public field 'lastIpToMgmt' missing"
        assert "localIp" not in agent, "Internal field 'localIp' leaked"


# ── Site field stripping ──────────────────────────────────────────────────────

@pytest.mark.critical
class TestSiteInternalFieldStripping:
    def test_list_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        sites = client.get("/web/api/v2.1/sites", headers=auth_headers).json()["data"]["sites"]
        assert sites, "Seed must produce at least one site"
        for site in sites:
            for field in SITE_INTERNAL_FIELDS:
                assert field not in site, (
                    f"CRITICAL: site internal field '{field}' leaked in list response"
                )

    def test_single_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        site_id = (
            client.get("/web/api/v2.1/sites", headers=auth_headers)
            .json()["data"]["sites"][0]["id"]
        )
        site = client.get(f"/web/api/v2.1/sites/{site_id}", headers=auth_headers).json()["data"]
        for field in SITE_INTERNAL_FIELDS:
            assert field not in site


# ── Group field stripping ─────────────────────────────────────────────────────

@pytest.mark.critical
class TestGroupInternalFieldStripping:
    def test_list_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        groups = client.get("/web/api/v2.1/groups", headers=auth_headers).json()["data"]
        assert groups
        for group in groups:
            for field in GROUP_INTERNAL_FIELDS:
                assert field not in group, (
                    f"CRITICAL: group internal field '{field}' leaked"
                )


# ── User field stripping ──────────────────────────────────────────────────────

@pytest.mark.critical
class TestUserInternalFieldStripping:
    def test_list_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        users = client.get("/web/api/v2.1/users", headers=auth_headers).json()["data"]
        assert users
        for user in users:
            for field in USER_INTERNAL_FIELDS:
                assert field not in user, (
                    f"CRITICAL: user internal field '{field}' leaked"
                )

    def test_api_token_field_is_always_null(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Real S1 API always returns apiToken: null — never expose the stored token."""
        for user in client.get("/web/api/v2.1/users", headers=auth_headers).json()["data"]:
            assert user.get("apiToken") is None, "apiToken must always be null in responses"
            assert "_apiToken" not in user, "Private _apiToken must never appear in responses"


# ── Exclusion field stripping ─────────────────────────────────────────────────

@pytest.mark.critical
class TestExclusionInternalFieldStripping:
    def test_list_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        exclusions = client.get("/web/api/v2.1/exclusions", headers=auth_headers).json()["data"]
        assert exclusions
        for excl in exclusions:
            for field in EXCLUSION_INTERNAL_FIELDS:
                assert field not in excl, (
                    f"CRITICAL: exclusion internal field '{field}' leaked"
                )


# ── Firewall field stripping ──────────────────────────────────────────────────

@pytest.mark.critical
class TestFirewallInternalFieldStripping:
    def test_list_endpoint_strips_all_internal_fields(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        rules = client.get("/web/api/v2.1/firewall-control", headers=auth_headers).json()["data"]
        assert rules
        for rule in rules:
            for field in FIREWALL_INTERNAL_FIELDS:
                assert field not in rule, (
                    f"CRITICAL: firewall rule internal field '{field}' leaked"
                )


# ── Auth critical paths ───────────────────────────────────────────────────────

@pytest.mark.critical
class TestAuthCriticalPaths:
    """Authentication must reject every unauthenticated or malformed request."""

    _GUARDED = [
        "/web/api/v2.1/agents",
        "/web/api/v2.1/threats",
        "/web/api/v2.1/sites",
        "/web/api/v2.1/groups",
        "/web/api/v2.1/exclusions",
        "/web/api/v2.1/users",
        "/web/api/v2.1/firewall-control",
        "/web/api/v2.1/activities",
        "/web/api/v2.1/cloud-detection/alerts",
    ]

    def test_all_guarded_endpoints_reject_no_header(self, client: TestClient) -> None:
        for path in self._GUARDED:
            assert client.get(path).status_code == 401, f"{path} accepted unauthenticated request"

    def test_all_guarded_endpoints_reject_wrong_scheme(self, client: TestClient) -> None:
        headers = {"Authorization": "Bearer admin-token-0000-0000-000000000001"}
        for path in self._GUARDED:
            assert client.get(path, headers=headers).status_code == 401, (
                f"{path} accepted Bearer token (should require ApiToken scheme)"
            )

    def test_all_guarded_endpoints_reject_invalid_token(self, client: TestClient) -> None:
        headers = {"Authorization": "ApiToken totally-invalid-token-xyz"}
        for path in self._GUARDED:
            assert client.get(path, headers=headers).status_code == 401, (
                f"{path} accepted an invalid ApiToken"
            )

    def test_admin_token_accepted_everywhere(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        for path in self._GUARDED:
            assert client.get(path, headers=auth_headers).status_code == 200, (
                f"{path} rejected valid admin ApiToken"
            )

    def test_viewer_token_accepted_everywhere(
        self, client: TestClient, viewer_headers: dict
    ) -> None:
        for path in self._GUARDED:
            assert client.get(path, headers=viewer_headers).status_code == 200, (
                f"{path} rejected valid viewer ApiToken"
            )
