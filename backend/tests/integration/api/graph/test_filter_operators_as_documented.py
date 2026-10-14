"""`$filter` takes the operators each product documents, and Defender only its filterable properties.

Graph documents `in` -- `~/users?$filter=mail in ('mail1@domain.com',
'mail2@domain.com')` -- and lambdas over collections of primitives, where the
range variable is the member itself: `~/groups?$filter=groupTypes/any(c:c eq
'Unified')`, `~/users?$filter=businessPhones/any(p:startswith(p, '44'))`
(https://learn.microsoft.com/en-us/graph/filter-query-parameter). Its own
example of the sub-property form compares an unquoted GUID:
`assignedLicenses/any(s:s/skuId eq 184efa21-...)`. The mock refused all four
with a parse error.

Defender documents neither `in` nor lambdas, and says "Not all properties are
filterable" (https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-odata-samples);
each collection page lists the ones that are. The mock filtered on anything
the record carried.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


class TestGraphIn:
    """`field in (...)` matches any listed value."""

    def test_in_returns_exactly_the_listed_users(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        users = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                           params={"$top": 999}).json()["value"]
        wanted = [users[0]["userPrincipalName"], users[3]["userPrincipalName"]]
        quoted = ", ".join(f"'{u}'" for u in wanted)
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$filter": f"userPrincipalName in ({quoted})"})
        assert response.status_code == 200, response.text
        assert sorted(u["userPrincipalName"] for u in response.json()["value"]) == sorted(wanted)


class TestGraphPrimitiveLambda:
    """`coll/any(x: x eq 'v')` and `coll/any(x: startswith(x, 'v'))`."""

    def test_group_types_any_eq_unified(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        groups = client.get("/graph/v1.0/groups", headers=graph_admin_headers,
                            params={"$top": 999}).json()["value"]
        expected = sorted(g["id"] for g in groups if "Unified" in (g.get("groupTypes") or []))
        assert expected, "the seed has Microsoft 365 groups"
        response = client.get("/graph/v1.0/groups", headers=graph_admin_headers,
                              params={"$filter": "groupTypes/any(c:c eq 'Unified')"})
        assert response.status_code == 200, response.text
        assert sorted(g["id"] for g in response.json()["value"]) == expected

    def test_any_with_startswith(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get(
            "/graph/v1.0/groups", headers=graph_admin_headers,
            params={"$filter": "groupTypes/any(c:startswith(c, 'Uni'))"},
        )
        assert response.status_code == 200, response.text
        assert all("Unified" in g["groupTypes"] for g in response.json()["value"])

    def test_sub_property_lambda_takes_an_unquoted_guid(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        users = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                           params={"$top": 999}).json()["value"]
        licensed = next(u for u in users if u.get("assignedLicenses"))
        sku = licensed["assignedLicenses"][0]["skuId"]
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$filter": f"assignedLicenses/any(s:s/skuId eq {sku})"})
        assert response.status_code == 200, response.text
        assert licensed["id"] in {u["id"] for u in response.json()["value"]}


class TestDefenderFilterable:
    """Only the listed properties filter; `in` is not Defender's."""

    @staticmethod
    def _headers(client: TestClient) -> dict[str, str]:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_a_listed_property_filters(self, client: TestClient) -> None:
        response = client.get("/mde/api/machines", headers=self._headers(client),
                              params={"$filter": "healthStatus eq 'Active'"})
        assert response.status_code == 200

    def test_an_unlisted_property_is_an_odata_error(self, client: TestClient) -> None:
        response = client.get("/mde/api/alerts", headers=self._headers(client),
                              params={"$filter": "machineId eq 'abc'"})
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "ODataError"
        assert "machineId" in error["message"]

    def test_machine_os_build_is_not_filterable(self, client: TestClient) -> None:
        response = client.get("/mde/api/machines", headers=self._headers(client),
                              params={"$filter": "osBuild gt 1"})
        assert response.status_code == 400

    def test_casing_follows_the_docs_loosely(self, client: TestClient) -> None:
        response = client.get("/mde/api/alerts", headers=self._headers(client),
                              params={"$filter": "InvestigationId eq 1"})
        assert response.status_code == 200

    def test_in_is_not_defenders(self, client: TestClient) -> None:
        response = client.get("/mde/api/machines", headers=self._headers(client),
                              params={"$filter": "healthStatus in ('Active')"})
        assert response.status_code == 400
