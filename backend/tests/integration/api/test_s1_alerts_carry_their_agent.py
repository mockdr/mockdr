"""A cloud-detection alert carries agentRealtimeInfo, as recorded replies do.

The 2.1 swagger's AlertInformationSchema omits it and the strict shaping
dropped it. XSOAR's SentinelOne-V2 reads it without a guard (`get_alerts`:
`agent_realtime_info.get("name")`), so `sentinelone-get-alerts` raised
AttributeError on the mock. Real replies carry it: demisto/content's
SentinelOneEventCollector `test_data/alerts.json` and the captures in
elastic/integrations' sentinel_one alert pipeline tests, with the members
below.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

MEMBERS = {"id", "infected", "isActive", "isDecommissioned", "machineType", "name", "os", "uuid"}


def test_every_alert_names_its_agent(client: TestClient, auth_headers: dict) -> None:
    alerts = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                        params={"limit": 100}).json()["data"]
    assert alerts
    for alert in alerts:
        info = alert["agentRealtimeInfo"]
        assert set(info) == MEMBERS
        assert info["id"] and info["name"]


def test_the_agent_is_the_one_the_agents_api_answers(
    client: TestClient, auth_headers: dict,
) -> None:
    info = client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                      params={"limit": 1}).json()["data"][0]["agentRealtimeInfo"]
    (agent,) = client.get("/web/api/v2.1/agents", headers=auth_headers,
                          params={"ids": info["id"]}).json()["data"]
    assert (info["name"], info["uuid"], info["machineType"]) == (
        agent["computerName"], agent["uuid"], agent["machineType"])


def test_xsoar_get_alerts_reads_what_it_reads(client: TestClient, auth_headers: dict) -> None:
    """The members SentinelOne-V2's get_alerts dereferences, unguarded."""
    for alert in client.get("/web/api/v2.1/cloud-detection/alerts", headers=auth_headers,
                            params={"limit": 100}).json()["data"]:
        realtime = alert.get("agentRealtimeInfo")
        assert realtime.get("name") is not None
        assert realtime.get("id") is not None
        assert "os" in realtime
        assert alert.get("ruleInfo").get("name") is not None
        assert alert.get("alertInfo").get("alertId") is not None
