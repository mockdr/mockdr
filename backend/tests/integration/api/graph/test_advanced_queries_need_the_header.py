"""Directory queries that only work as advanced queries, and `$count` without the header.

Graph serves some directory queries only through its advanced-query index:
"The requestor must set the ConsistencyLevel header to eventual and, except
for $search, use the $count query parameter"
(https://learn.microsoft.com/en-us/graph/aad-advanced-queries). The listed
scenarios include `$search`, `$filter` with `endsWith`, with `ne` and `not`,
and `$filter` together with `$orderby`; without the parameters "the request
returns an error", `400 Request_UnsupportedQuery`, and the page quotes the
`$search` and `endsWith` messages.

The mock checked the header only for `$count` and answered every one of these
for any caller, so an integration could ship a query production refuses. And
for `$count` it had it the wrong way round: the same page says Graph
"silently ignores the $count query parameter (?$count=true)" without the
header -- a 200 without `@odata.count` -- where the mock answered 400.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

_EVENTUAL = {"ConsistencyLevel": "eventual"}


class TestSearchNeedsConsistencyLevel:
    """`$search` on users and groups without the header is refused."""

    def test_users_search_without_header_is_unsupported_query(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$search": '"displayName:a"'})
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "Request_UnsupportedQuery"
        assert "ConsistencyLevel: eventual" in error["message"]

    def test_groups_search_without_header_is_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/groups", headers=graph_admin_headers,
                              params={"$search": '"displayName:a"'})
        assert response.status_code == 400

    def test_search_with_header_still_answers(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users",
                              headers={**graph_admin_headers, **_EVENTUAL},
                              params={"$search": '"displayName:a"'})
        assert response.status_code == 200


class TestAdvancedFiltersNeedBothParameters:
    """`endsWith`, `ne`, `not` and `$filter`+`$orderby` need header and `$count`."""

    def test_endswith_without_advanced_parameters_is_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$filter": "endsWith(mail,'.internal')"})
        assert response.status_code == 400
        assert response.json()["error"]["message"].startswith("Operator 'endsWith'")

    def test_ne_with_header_but_without_count_is_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users",
                              headers={**graph_admin_headers, **_EVENTUAL},
                              params={"$filter": "accountEnabled ne true"})
        assert response.status_code == 400

    def test_filter_and_orderby_together_are_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/groups", headers=graph_admin_headers,
                              params={"$filter": "securityEnabled eq true",
                                      "$orderby": "displayName"})
        assert response.status_code == 400

    def test_a_quoted_ne_is_not_an_operator(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$filter": "displayName eq 'one ne two'"})
        assert response.status_code == 200

    def test_ne_as_an_advanced_query_answers(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users",
                              headers={**graph_admin_headers, **_EVENTUAL},
                              params={"$filter": "accountEnabled ne true", "$count": "true"})
        assert response.status_code == 200
        body = response.json()
        assert body["@odata.count"] == len(body["value"])
        assert all(u["accountEnabled"] is False for u in body["value"])


class TestCountWithoutHeaderIsIgnored:
    """`?$count=true` without the header is a 200 with no `@odata.count`."""

    def test_users_count_without_header_answers_without_a_count(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$count": "true"})
        assert response.status_code == 200
        assert "@odata.count" not in response.json()

    def test_groups_count_with_header_counts(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/groups",
                              headers={**graph_admin_headers, **_EVENTUAL},
                              params={"$count": "true", "$top": 999})
        assert response.status_code == 200
        body = response.json()
        assert body["@odata.count"] == len(body["value"])
