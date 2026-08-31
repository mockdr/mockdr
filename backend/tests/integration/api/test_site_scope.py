"""A user scoped to a site sees that site, and no other.

`scope` is declared with the enum `["tenant", "account", "site"]` and this
mock answered `scope: "site"` and the site roles that go with it while
showing that caller every site's records: a Viewer confined to one site of
three read all sixty agents. `TenantScopeMiddleware` already enforced the
account axis, and its own comment records why — "the scoping was inert and
every caller saw the whole store". This is that sentence one axis over.

The account axis is invisible here on purpose: this mock seeds one account,
so confining to it removes nothing. Three sites is what makes the site axis
measurable at all.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


@pytest.fixture
def sites(client: TestClient, auth_headers: dict) -> list[dict]:
    response = client.get(f"{BASE}/sites", headers=auth_headers, params={"limit": "10"})
    assert response.status_code == 200, response.text
    found = response.json()["data"]["sites"]
    assert len(found) >= 2, "two sites are needed to tell confinement from its absence"
    return found


def _scoped_headers(
    client: TestClient, auth_headers: dict, site_ids: list[str], label: str,
) -> dict:
    body = {
        "fullName": f"zzz scoped {label}",
        "email": f"zzz-scoped-{label}@example.test",
        "role": "Viewer",
        "scope": "site",
        "siteRoles": [{"id": site_id} for site_id in site_ids],
    }
    response = client.post(f"{BASE}/users", headers=auth_headers, json={"data": body})
    assert response.status_code in (200, 201), response.text
    return {"Authorization": f"ApiToken {response.json()['data']['apiToken']}"}


def _agent_sites(client: TestClient, headers: dict, **params: str) -> list[str]:
    response = client.get(f"{BASE}/agents", headers=headers, params={"limit": "100", **params})
    assert response.status_code == 200, response.text
    return sorted({a["siteId"] for a in response.json()["data"]})


class TestASiteScopedCallerSeesOneSite:
    def test_only_the_site_they_are_scoped_to(
        self, client: TestClient, auth_headers: dict, sites: list[dict],
    ) -> None:
        everything = _agent_sites(client, auth_headers)
        assert len(everything) > 1, "one site cannot show confinement"
        headers = _scoped_headers(client, auth_headers, [sites[0]["id"]], "one")
        assert _agent_sites(client, headers) == [sites[0]["id"]]

    def test_two_sites_when_they_hold_two_roles(
        self, client: TestClient, auth_headers: dict, sites: list[dict],
    ) -> None:
        wanted = [sites[0]["id"], sites[1]["id"]]
        headers = _scoped_headers(client, auth_headers, wanted, "two")
        assert _agent_sites(client, headers) == sorted(wanted)

    def test_asking_for_another_site_does_not_reach_it(
        self, client: TestClient, auth_headers: dict, sites: list[dict],
    ) -> None:
        """A caller may narrow within their own scope and no further."""
        headers = _scoped_headers(client, auth_headers, [sites[0]["id"]], "narrow")
        assert _agent_sites(client, headers, siteIds=sites[1]["id"]) == [sites[0]["id"]]

    def test_naming_their_own_account_does_not_lift_the_site_scope(
        self, client: TestClient, auth_headers: dict, sites: list[dict],
    ) -> None:
        """The two axes were two branches, and the account one returned first.

        A console sends `accountIds` as a matter of course, so this was not an
        exotic bypass: it was the ordinary query string, and it took the site
        confinement off entirely.
        """
        headers = _scoped_headers(client, auth_headers, [sites[0]["id"]], "acct")
        account_id = client.get(
            f"{BASE}/accounts", headers=auth_headers,
        ).json()["data"][0]["id"]
        assert _agent_sites(client, headers, accountIds=account_id) == [sites[0]["id"]]

    def test_a_percent_encoded_value_survives_the_rewrite(
        self, client: TestClient, auth_headers: dict, sites: list[dict],
    ) -> None:
        """The query was rebuilt with an f-string, which lost the escaping.

        A `%26` inside a value became a parameter separator, so the filter was
        truncated and whatever followed it — `limit`, here — was silently
        applied instead.
        """
        headers = _scoped_headers(client, auth_headers, [sites[0]["id"]], "encode")
        response = client.get(
            f"{BASE}/agents", headers=headers,
            params={"limit": "100", "computerName__contains": "A&limit=1"},
        )
        assert response.status_code == 200, response.text
        assert response.json()["pagination"]["totalItems"] == 0

    def test_asking_for_their_own_site_still_works(
        self, client: TestClient, auth_headers: dict, sites: list[dict],
    ) -> None:
        headers = _scoped_headers(client, auth_headers, [sites[0]["id"]], "own")
        assert _agent_sites(client, headers, siteIds=sites[0]["id"]) == [sites[0]["id"]]


class TestTheOtherScopesAreUntouched:
    def test_a_tenant_scoped_viewer_still_sees_every_site(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """Only `scope: "site"` confines; the account axis is enforced already."""
        response = client.post(f"{BASE}/users", headers=auth_headers, json={"data": {
            "fullName": "zzz tenant viewer", "email": "zzz-tenant@example.test",
            "role": "Viewer", "scope": "tenant",
        }})
        assert response.status_code in (200, 201), response.text
        headers = {"Authorization": f"ApiToken {response.json()['data']['apiToken']}"}
        assert _agent_sites(client, headers) == _agent_sites(client, auth_headers)

    def test_an_admin_still_sees_every_site(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        assert len(_agent_sites(client, auth_headers)) > 1
