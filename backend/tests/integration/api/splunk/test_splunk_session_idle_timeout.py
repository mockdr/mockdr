"""A Splunk session key times out after an hour unused, not eight hours after login.

server.conf ``[general] sessionTimeout`` defaults to one hour (Splunk 10.4
server.conf.spec) and is "the maximum idle time in the interaction" (Admin
Manual, "Configure user session timeouts"): every use restarts it. The mock
counted eight hours from login regardless of use, so a poller that logs in
once refused mid-run, and a key idle for seven hours still worked.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from api.splunk_auth import reap_sessions
from repository.store import store
from tests.clock import Clock

_INFO = "/splunk/services/server/info"


def _login(client: TestClient) -> dict[str, str]:
    response = client.post("/splunk/services/auth/login",
                           data={"username": "admin", "password": "mockdr-admin"})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Splunk {response.json()['sessionKey']}"}


def test_a_busy_session_outlives_eight_hours(client: TestClient, clock: Clock) -> None:
    headers = _login(client)
    for _ in range(10):
        clock.advance(3000)
        assert client.get(_INFO, headers=headers).status_code == 200


def test_an_idle_session_times_out_after_an_hour(client: TestClient, clock: Clock) -> None:
    headers = _login(client)
    clock.advance(3601)

    response = client.get(_INFO, headers=headers)
    assert response.status_code == 401
    assert response.json()["messages"][0]["text"] == "call not properly authenticated"


def test_idle_sessions_are_reaped(client: TestClient, clock: Clock) -> None:
    _login(client)
    busy = _login(client)
    clock.advance(2000)
    client.get(_INFO, headers=busy)
    clock.advance(2000)

    assert reap_sessions() == 1
    assert store.count("splunk_sessions") == 1
    assert client.get(_INFO, headers=busy).status_code == 200
