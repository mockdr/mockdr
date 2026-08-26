"""A query naming a property the resource does not have.

`$select=notAField` answered a page of empty objects, `$filter=notAField eq
'x'` an empty collection and `$orderby=notAField` an unsorted one. All three
are `200`s, and all three read as "nothing matched" — which is what a client
with a typo in a property name concluded, on both OData mounts.

What each resource carries is read from the vendored references rather than
written down here: Graph's from the reduced v1.0 reference, which records the
properties of the resource each route answers, and Defender's from its docs'
recorded response paths. A route neither speaks for is not judged, because a
refusal has to be able to say what the resource *does* carry.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def graph(client: TestClient) -> dict:
    """App-only Graph headers."""
    token = client.post("/graph/oauth2/v2.0/token", data={
        "client_id": "graph-mock-admin-client",
        "client_secret": "graph-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def defender(client: TestClient) -> dict:
    """Defender headers."""
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client",
        "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestGraphRefusesAnUnknownProperty:
    """Graph answers `Could not find a property named 'x'`."""

    ALERTS = "/graph/v1.0/security/alerts_v2"

    @pytest.mark.parametrize("parameter,value", [
        ("$select", "notAField"),
        ("$filter", "notAField eq 'x'"),
        ("$orderby", "notAField desc"),
    ])
    def test_each_query_option_is_judged(
        self, client: TestClient, graph: dict, parameter: str, value: str,
    ) -> None:
        resp = client.get(self.ALERTS, headers=graph, params={parameter: value})
        assert resp.status_code == 400
        assert "notAField" in resp.json()["error"]["message"]

    def test_a_property_the_resource_has_is_answered(
        self, client: TestClient, graph: dict,
    ) -> None:
        resp = client.get(
            self.ALERTS, headers=graph, params={"$select": "title,severity"},
        )
        assert resp.status_code == 200
        assert set(resp.json()["value"][0]) <= {"title", "severity"}

    def test_a_documented_property_this_mock_does_not_answer_is_still_valid(
        self, client: TestClient, graph: dict,
    ) -> None:
        """`productName` is a property of a Graph alert that this install does
        not fill in. Refusing it would be inventing a failure — the judgement
        comes from the vendor's property list, not from what mockdr seeds."""
        resp = client.get(self.ALERTS, headers=graph, params={"$select": "productName"})
        assert resp.status_code == 200

    def test_a_lambda_over_a_collection_names_the_collection(
        self, client: TestClient, graph: dict,
    ) -> None:
        resp = client.get(
            "/graph/v1.0/security/incidents", headers=graph,
            params={"$filter": "alerts/any(a: a/severity eq 'high')"},
        )
        assert resp.status_code == 200

    def test_another_route_is_judged_by_its_own_resource(
        self, client: TestClient, graph: dict,
    ) -> None:
        """`displayName` is a user's, not an alert's."""
        assert client.get(
            "/graph/v1.0/users", headers=graph, params={"$select": "displayName"},
        ).status_code == 200
        assert client.get(
            "/graph/v1.0/users", headers=graph, params={"$select": "severity"},
        ).status_code == 400

    def test_the_paging_options_are_not_property_names(
        self, client: TestClient, graph: dict,
    ) -> None:
        resp = client.get(
            "/graph/v1.0/users", headers=graph, params={"$top": "2", "$skip": "1"},
        )
        assert resp.status_code == 200


class TestDefenderRefusesAnUnknownProperty:
    """The same on the Defender mount, from its own documented properties."""

    def test_select_is_judged(self, client: TestClient, defender: dict) -> None:
        resp = client.get(
            "/mde/api/machines", headers=defender, params={"$select": "notAField"},
        )
        assert resp.status_code == 400
        assert "notAField" in resp.json()["error"]["message"]

    def test_filter_is_judged(self, client: TestClient, defender: dict) -> None:
        resp = client.get(
            "/mde/api/alerts", headers=defender, params={"$filter": "nope eq 'x'"},
        )
        assert resp.status_code == 400

    def test_a_real_property_still_selects(
        self, client: TestClient, defender: dict,
    ) -> None:
        resp = client.get(
            "/mde/api/machines", headers=defender, params={"$select": "computerDnsName"},
        )
        assert resp.status_code == 200
        assert set(resp.json()["value"][0]) == {"computerDnsName"}

    def test_a_real_filter_still_filters(
        self, client: TestClient, defender: dict,
    ) -> None:
        resp = client.get(
            "/mde/api/machines", headers=defender,
            params={"$filter": "healthStatus eq 'Active'"},
        )
        assert resp.status_code == 200
        assert all(m["healthStatus"] == "Active" for m in resp.json()["value"])
