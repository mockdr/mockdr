"""Integration tests for live EDR→SIEM bridging (ADR-009).

The bridge subscribes to domain events at startup; EDR commands publish after
mutating. These tests exercise the whole path — an EDR mutation over HTTP must
show up in Splunk and Sentinel without any further call.
"""
from fastapi.testclient import TestClient

from repository.splunk.splunk_event_repo import splunk_event_repo


def _mde_headers(client: TestClient) -> dict[str, str]:
    """Authenticate against MDE and return Bearer headers."""
    resp = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestMdeAlertBridging:
    """A Defender alert created over the API reaches the SIEMs."""

    def test_new_alert_produces_a_splunk_event(self, client: TestClient) -> None:
        before = len(splunk_event_repo.list_all())

        resp = client.post(
            "/mde/api/alerts/createAlertByReference",
            headers=_mde_headers(client),
            json={
                "machineId": "machine-bridge-test",
                "severity": "High",
                "title": "Bridge test alert",
                "category": "SuspiciousActivity",
            },
        )
        assert resp.status_code == 200

        after = splunk_event_repo.list_all()
        assert len(after) > before, "the alert never reached Splunk"
        assert any(
            "Bridge test alert" in str(getattr(event, "raw", ""))
            or "Bridge test alert" in str(getattr(event, "event_data", ""))
            for event in after
        ), "the bridged event does not carry the alert"


class TestScenarioBridging:
    """Scenario mutations are visible in the SIEM, as a SOAR test expects."""

    def test_mass_infection_reaches_splunk(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        before = len(splunk_event_repo.list_all())
        resp = client.post(
            "/web/api/v2.1/_dev/scenario",
            headers=auth_headers,
            json={"scenario": "mass_infection"},
        )
        assert resp.status_code == 200
        assert len(splunk_event_repo.list_all()) > before

    def test_bridge_failure_cannot_break_the_edr_command(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """Error isolation per ADR-010: a broken subscriber must not surface."""
        from domain.event_bus import event_bus

        def explode(event: object) -> None:
            raise RuntimeError("subscriber boom")

        event_bus.subscribe("agent_updated", explode)
        try:
            resp = client.post(
                "/web/api/v2.1/_dev/scenario",
                headers=auth_headers,
                json={"scenario": "agent_offline"},
            )
            assert resp.status_code == 200
        finally:
            event_bus._subscribers["agent_updated"].remove(explode)
