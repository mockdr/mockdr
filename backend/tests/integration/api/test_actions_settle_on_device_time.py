"""An action finishes on the device's time, not when its own API is next read.

Falcon containment, SentinelOne connect/disconnect, Cortex isolation,
Defender machine actions and Elastic response actions settle about a second
after they are asked for — but only did so when their own API next read the
record. A consumer that confirms through the SIEM (ADR-009), or reads
nothing for a day, saw the transitional state for good, and a late read
stamped the completion at the moment it happened to notice.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from application.dev.commands import export_state, import_state
from infrastructure import housekeeping
from repository.agent_repo import agent_repo
from repository.cs_host_repo import cs_host_repo
from tests.clock import Clock

S1 = "/web/api/v2.1"
ADMIN = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}
SPLUNK = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


def _splunk(client: TestClient, search: str) -> list[dict]:
    response = client.post("/splunk/services/search/jobs?output_mode=json", headers=SPLUNK,
                           data={"search": search, "exec_mode": "oneshot"})
    assert response.status_code == 200, response.text
    return list(response.json()["results"])


def _connected_agent() -> str:
    return next(a.id for a in agent_repo.list_all() if a.networkStatus == "connected")


def test_a_disconnect_reaches_splunk_settled_with_nobody_reading_s1(
    client: TestClient, clock: Clock,
) -> None:
    agent_id = _connected_agent()
    asked = clock.time()
    client.post(f"{S1}/agents/actions/disconnect", headers=ADMIN,
                json={"filter": {"ids": [agent_id]}})
    clock.advance(days=1)

    rows = _splunk(client, f'search index=sentinelone sourcetype="sentinelone:channel:agents" '
                           f'id="{agent_id}" networkStatus=disconnected')
    assert rows, "the settled state never reached the SIEM"
    # Dated when the agent answered, not a day later when the SIEM was read.
    indexed = datetime.fromisoformat(str(rows[0]["_time"])).timestamp()
    assert abs(indexed - (asked + 1)) < 5, rows[0]["_time"]


def test_an_isolation_reaches_splunk_settled_with_nobody_reading_cortex(
    client: TestClient, clock: Clock,
) -> None:
    endpoints = client.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=XDR,
                            json={"request_data": {}}).json()["reply"]["endpoints"]
    target = next(e for e in endpoints if e["is_isolated"] == "AGENT_UNISOLATED")["endpoint_id"]
    client.post("/xdr/public_api/v1/endpoints/isolate", headers=XDR,
                json={"request_data": {"endpoint_id": target}})
    clock.advance(days=1)

    rows = _splunk(client, f'search index=cortex_xdr sourcetype="pan:xdr:endpoint" '
                           f'endpoint_id="{target}" is_isolated=AGENT_ISOLATED')
    assert rows, "Splunk still says AGENT_PENDING_ISOLATION"


def test_a_defender_action_unread_for_a_day_completed_a_second_in(
    client: TestClient, clock: Clock,
) -> None:
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client", "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    machine = client.get("/mde/api/machines?$top=1", headers=headers).json()["value"][0]["id"]
    action = client.post(f"/mde/api/machines/{machine}/runAntiVirusScan", headers=headers,
                         json={"Comment": "settle", "ScanType": "Quick"}).json()
    clock.advance(days=1)
    housekeeping.sweep()
    headers = {"Authorization": "Bearer " + client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client", "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]}

    done = client.get(f"/mde/api/machineactions/{action['id']}", headers=headers).json()
    assert done["status"] == "Succeeded"

    def parse(text: str) -> datetime:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)

    took = parse(done["lastUpdateDateTimeUtc"]) - parse(done["creationDateTimeUtc"])
    assert took < timedelta(seconds=5), took


def test_the_sweep_settles_containment_nobody_polls(client: TestClient, clock: Clock) -> None:
    host = next(h for h in cs_host_repo.list_all() if h.status == "normal")
    token = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
    }).json()["access_token"]
    client.post("/cs/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "contain"}, json={"ids": [host.device_id]})
    clock.advance(2)

    assert housekeeping.sweep()["settled"] >= 1
    assert cs_host_repo.get(host.device_id).status == "contained"  # type: ignore[union-attr]


def test_a_transition_in_flight_survives_a_restart(client: TestClient, clock: Clock) -> None:
    """Export, a fresh module and import: what MOCKDR_PERSIST does across a restart."""
    import importlib

    from application.agents import network

    agent_id = _connected_agent()
    client.post(f"{S1}/agents/actions/disconnect", headers=ADMIN,
                json={"filter": {"ids": [agent_id]}})
    snapshot = export_state()
    importlib.reload(network)  # whatever the process held in memory is gone
    import_state(snapshot)
    clock.advance(2)

    agent = client.get(f"{S1}/agents?ids={agent_id}", headers=ADMIN).json()["data"][0]
    assert agent["networkStatus"] == "disconnected"
