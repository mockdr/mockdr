"""An import keeps the credentials this instance issued, as a reset does.

`/_dev/import` cleared the store and loaded the snapshot, so a partial one --
an agents-only fixture, say -- left no S1 API token at all. `/_dev/reset` and
`/_dev/import` both need an admin token, so nothing could put them back: every
client of the instance answered 401 until it was restarted.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def test_a_partial_snapshot_leaves_the_caller_signed_in(
    client: TestClient, auth_headers: dict,
) -> None:
    agents = client.get(f"{BASE}/_dev/export", headers=auth_headers).json()["agents"]
    resp = client.post(f"{BASE}/_dev/import", headers=auth_headers, json={"agents": agents})
    assert resp.status_code == 200, resp.text

    assert client.get(f"{BASE}/agents", headers=auth_headers).status_code == 200
    assert client.post(f"{BASE}/_dev/reset", headers=auth_headers).status_code == 200


def test_every_seeded_token_keeps_its_role(
    client: TestClient, auth_headers: dict, viewer_headers: dict,
) -> None:
    client.post(f"{BASE}/_dev/import", headers=auth_headers, json={})
    assert client.get(f"{BASE}/agents", headers=viewer_headers).status_code == 200
    # Still a viewer: kept, not promoted.
    assert client.post(f"{BASE}/_dev/reset", headers=viewer_headers).status_code == 403


def test_an_issued_oauth_token_survives_an_import(
    client: TestClient, auth_headers: dict,
) -> None:
    token = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
    }).json()["access_token"]
    client.post(f"{BASE}/_dev/import", headers=auth_headers, json={})
    resp = client.get("/cs/devices/queries/devices/v1",
                      headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_the_snapshots_own_tokens_are_loaded_too(
    client: TestClient, auth_headers: dict,
) -> None:
    snapshot = client.get(f"{BASE}/_dev/export", headers=auth_headers).json()
    snapshot["api_tokens"] = {"imported-token-1": {
        **next(iter(snapshot["api_tokens"].values())), "token": "imported-token-1",
    }}
    assert client.post(f"{BASE}/_dev/import", headers=auth_headers,
                       json=snapshot).status_code == 200
    assert client.get(f"{BASE}/agents",
                      headers={"Authorization": "ApiToken imported-token-1"}).status_code == 200
    assert client.get(f"{BASE}/agents", headers=auth_headers).status_code == 200
