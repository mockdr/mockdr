"""What an account says about its sites must be what its sites hold.

`totalLicenses` is "the total number of licenses on all Surfaces for all
Bundles", and nothing kept it: adding a fourth site of ten licences left the
account still answering the 1500 the first three hold. `numberOfSites` was
kept by an increment beside a decrement, which is one missed call site away
from the same drift. Both are counted from the sites now.

`activeAgents` is *not* part of this and is right as it stands: the field
name reads like a subset, and the swagger's description for it is "Total
Agents in the Account" — so 60 of 60, with 48 of them active, is the
vendor's own meaning.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _account(client: TestClient, headers: dict) -> dict:
    response = client.get(f"{BASE}/accounts", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"][0]


def _sites(client: TestClient, headers: dict) -> list[dict]:
    response = client.get(f"{BASE}/sites", headers=headers, params={"limit": "100"})
    assert response.status_code == 200, response.text
    return response.json()["data"]["sites"]


def _held(client: TestClient, headers: dict) -> tuple[int, int]:
    sites = _sites(client, headers)
    return len(sites), sum(int(s.get("totalLicenses") or 0) for s in sites)


class TestTheAccountCountsItsSites:
    def test_the_seeded_account_agrees_with_its_sites(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        account = _account(client, auth_headers)
        assert (account["numberOfSites"], account["totalLicenses"]) == _held(
            client, auth_headers,
        )

    def test_it_follows_a_create_an_update_and_a_delete(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        account_id = _account(client, auth_headers)["id"]
        before = _held(client, auth_headers)

        created = client.post(f"{BASE}/sites", headers=auth_headers, json={"data": {
            "name": "zzz-totals-site", "accountId": account_id,
            "siteType": "Paid", "suite": "Complete", "totalLicenses": 10,
        }})
        assert created.status_code in (200, 201), created.text
        site_id = created.json()["data"]["id"]
        account = _account(client, auth_headers)
        assert (account["numberOfSites"], account["totalLicenses"]) == _held(
            client, auth_headers,
        )
        assert account["totalLicenses"] == before[1] + 10

        changed = client.put(f"{BASE}/sites/{site_id}", headers=auth_headers,
                             json={"data": {"totalLicenses": 90}})
        assert changed.status_code == 200, changed.text
        account = _account(client, auth_headers)
        assert account["totalLicenses"] == before[1] + 90

        removed = client.delete(f"{BASE}/sites/{site_id}", headers=auth_headers)
        assert removed.status_code in (200, 204), removed.text
        assert (
            _account(client, auth_headers)["numberOfSites"],
            _account(client, auth_headers)["totalLicenses"],
        ) == before


class TestActiveAgentsMeansWhatTheSwaggerSaysItMeans:
    def test_it_is_every_agent_in_the_account(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """"Total Agents in the Account" — the name is the misleading part."""
        agents = client.get(
            f"{BASE}/agents", headers=auth_headers, params={"limit": "100"},
        ).json()["data"]
        active = [a for a in agents if a.get("isActive")]
        assert len(active) < len(agents), "the seed cannot tell the two apart"
        assert _account(client, auth_headers)["activeAgents"] == len(agents)
