"""An `@odata.nextLink` is followed verbatim, and it must lead back to the same query.

Graph's paging contract: "Use the entire URL in the @odata.nextLink property
in a GET request to retrieve the next page of results ... Any other query
parameters that were present in the original request are also encoded in this
URL" (https://learn.microsoft.com/en-us/graph/paging). Every SDK pager does
exactly that.

The mock wrote the link as a fixed string on the production host --
`https://graph.microsoft.com/v1.0/users?$skip=100` -- and on Defender
`https://api.securitycenter.microsoft.com/api/machines?$top=..&$skip=..`. A
client following it left the mock for Microsoft; pointed back at the mock it
lost `$filter`, `$select`, `$orderby` and `$search`, so page two of a filtered
query was page two of the whole estate. The link is now the URL the client
called, with only the cursor advanced.

Directory objects add a second rule: they page with an opaque `$skiptoken`
and refuse `$skip` ("$skip isn't supported",
https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0;
"Directory objects such as user, group, and application don't support $skip",
https://learn.microsoft.com/en-us/graph/query-parameters#skip). The refusal
is `400 Request_BadRequest` "'$skip' is not supported by the service.", the
body recorded in
https://github.com/microsoftgraph/msgraph-sdk-powershell/issues/1420.
"""
from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient


def _walk(client: TestClient, url: str, headers: dict[str, str],
          params: dict[str, str | int]) -> tuple[list[dict], list[str]]:
    """Every row of a paged collection, following each nextLink verbatim."""
    rows: list[dict] = []
    links: list[str] = []
    response = client.get(url, headers=headers, params=params)
    while True:
        assert response.status_code == 200, response.text
        body = response.json()
        rows.extend(body["value"])
        link = body.get("@odata.nextLink")
        if not link:
            return rows, links
        links.append(link)
        assert len(links) < 200, "the walk never ended"
        response = client.get(link, headers=headers)


class TestGraphNextLinkCarriesTheQuery:
    """A filtered Graph collection walked by its links yields the filtered set."""

    def test_users_filtered_walk_returns_exactly_the_filtered_set(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        params = {"$filter": "accountEnabled eq true", "$select": "id,accountEnabled",
                  "$top": 3}
        whole = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                           params={"$filter": "accountEnabled eq true", "$top": 999}).json()
        expected = {u["id"] for u in whole["value"]}
        assert len(expected) > 3, "the seed must need more than one page"

        rows, links = _walk(client, "/graph/v1.0/users", graph_admin_headers, params)

        assert [r["id"] for r in rows] == [r["id"] for r in rows if r["id"] in expected]
        assert {r["id"] for r in rows} == expected
        assert len(rows) == len(expected), "a row came back twice"
        assert all(set(r) <= {"id", "accountEnabled", "@odata.type"} for r in rows), \
            "$select was dropped on a later page"
        for link in links:
            parts = urlsplit(link)
            assert parts.scheme and parts.netloc == "testserver", link
            assert parts.path == "/graph/v1.0/users", link
            query = parse_qs(parts.query)
            assert query["$filter"] == ["accountEnabled eq true"]
            assert query["$top"] == ["3"]
            assert "$skiptoken" in query and "$skip" not in query

    def test_a_skip_collection_keeps_skip_and_the_filter(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        """alerts_v2 documents `$skip`, so its link advances `$skip`."""
        url = "/graph/v1.0/security/alerts_v2"
        whole = client.get(url, headers=graph_admin_headers, params={"$top": 999}).json()["value"]
        severity = whole[0]["severity"]
        expected = [a["id"] for a in whole if a["severity"] == severity]
        assert len(expected) > 2

        rows, links = _walk(client, url, graph_admin_headers,
                            {"$filter": f"severity eq '{severity}'", "$top": 2})

        assert sorted(r["id"] for r in rows) == sorted(expected)
        assert links and all("$skip=" in link for link in links)

    def test_the_link_is_on_the_host_the_client_called(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        page = client.get("http://mock.example:9000/graph/v1.0/users",
                          headers=graph_admin_headers, params={"$top": 1}).json()
        assert page["@odata.nextLink"].startswith("http://mock.example:9000/graph/v1.0/users?")


class TestDirectoryObjectsRefuseSkip:
    """Directory collections page by `$skiptoken` and answer `$skip` with 400."""

    def test_skip_on_users_is_request_bad_request(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$skip": 1})
        assert response.status_code == 400
        error = response.json()["error"]
        assert error["code"] == "Request_BadRequest"
        assert error["message"] == "'$skip' is not supported by the service."

    def test_every_directory_collection_refuses_skip(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        for path in ("/graph/v1.0/groups", "/graph/v1.0/applications",
                     "/graph/v1.0/servicePrincipals", "/graph/v1.0/directoryRoles",
                     "/graph/v1.0/directory/administrativeUnits", "/graph/v1.0/organization",
                     "/graph/beta/users"):
            response = client.get(path, headers=graph_admin_headers, params={"$skip": 0})
            assert response.status_code == 400, path

    def test_a_forged_skiptoken_is_refused(
        self, client: TestClient, graph_admin_headers: dict[str, str],
    ) -> None:
        response = client.get("/graph/v1.0/users", headers=graph_admin_headers,
                              params={"$skiptoken": "not-a-token"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "Request_BadRequest"


class TestMdeNextLinkCarriesTheQuery:
    """Defender's link is the request's URL too, with `$skip` advanced."""

    def test_machines_filtered_walk_returns_exactly_the_filtered_set(
        self, client: TestClient,
    ) -> None:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        whole = client.get("/mde/api/machines", headers=headers,
                           params={"$top": 1000}).json()["value"]
        platform = whole[0]["osPlatform"]
        expected = {m["id"] for m in whole if m["osPlatform"] == platform}
        assert len(expected) > 2

        rows, links = _walk(client, "/mde/api/machines", headers,
                            {"$filter": f"osPlatform eq '{platform}'", "$top": 2})

        assert {r["id"] for r in rows} == expected
        assert len(rows) == len(expected)
        for link in links:
            parts = urlsplit(link)
            assert parts.netloc == "testserver" and parts.path == "/mde/api/machines", link
            assert parse_qs(parts.query)["$filter"] == [f"osPlatform eq '{platform}'"]
