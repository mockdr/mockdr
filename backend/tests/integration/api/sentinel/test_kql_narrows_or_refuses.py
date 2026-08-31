"""A KQL clause narrows the result, or the query is refused.

The parser dropped everything it did not recognise and ran the rest, which
is the one behaviour a query language must not have: a dropped predicate
*widens* the answer. `| where SourceSystem contains 'zzzzz'` returned all
210 rows of `SentinelOne_CL`, every one of them looking to the client like a
match, and `| distinct SourceSystem` returned the whole table rather than
its three values. Both answered 200.

Found by running the four analytics rules this mock ships as a client would
— read the rule, run its query. Two named tables that do not exist and the
other two matched nothing, so every shipped rule told a client the
workspace was empty.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

SENTINEL_PREFIX = "/sentinel"
QUERY = f"{SENTINEL_PREFIX}/v1/workspaces/mockdr-workspace/query"
_WS = (
    "/subscriptions/00000000-0000-0000-0000-000000000000"
    "/resourceGroups/mockdr-rg"
    "/providers/Microsoft.OperationalInsights/workspaces/mockdr-workspace"
    "/providers/Microsoft.SecurityInsights"
)


def _auth(client: TestClient) -> dict[str, str]:
    resp = client.post(
        f"{SENTINEL_PREFIX}/oauth2/v2.0/token",
        data={"client_id": "sentinel-mock-client-id",
              "client_secret": "sentinel-mock-client-secret",
              "grant_type": "client_credentials",
              "scope": "https://management.azure.com/.default"},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


def _rows(client: TestClient, kql: str) -> list[list[object]]:
    resp = client.post(QUERY, json={"query": kql}, headers=_auth(client))
    assert resp.status_code == 200, resp.text
    tables = resp.json()["tables"]
    return list(tables[0]["rows"]) if tables else []


def _refusal(client: TestClient, kql: str) -> str:
    resp = client.post(QUERY, json={"query": kql}, headers=_auth(client))
    assert resp.status_code == 400, resp.text
    return str(resp.json()["error"]["message"])


class TestEveryShippedRuleRuns:
    """The rules this workspace publishes, run the way a client runs them."""

    def test_each_one_resolves_and_matches_something(
        self, client: TestClient,
    ) -> None:
        rules = client.get(f"{SENTINEL_PREFIX}{_WS}/alertRules",
                           headers=_auth(client)).json()["value"]
        queries = [
            (r["name"], (r.get("properties") or {}).get("query"))
            for r in rules
            if (r.get("properties") or {}).get("query")
        ]
        assert len(queries) >= 4, "no scheduled rules to run"

        empty: list[str] = []
        for name, kql in queries:
            resp = client.post(QUERY, json={"query": kql}, headers=_auth(client))
            if resp.status_code != 200:
                empty.append(f"{name}: {resp.status_code} {resp.text[:90]}")
                continue
            tables = resp.json()["tables"]
            if not tables or not tables[0]["rows"]:
                empty.append(f"{name}: 200 with no rows — {kql}")
        assert empty == []


class TestAPredicateNarrows:
    def test_contains_matches_a_substring_and_nothing_else(
        self, client: TestClient,
    ) -> None:
        everything = len(_rows(client, "SentinelOne_CL"))
        some = len(_rows(
            client, "SentinelOne_CL | where SourceSystem contains 'threats'"))
        none = len(_rows(
            client, "SentinelOne_CL | where SourceSystem contains 'zzzzz'"))
        assert none == 0
        assert 0 < some < everything

    def test_a_number_compares_as_a_number(self, client: TestClient) -> None:
        """Compared as text, "100" sorts below "3" and was dropped."""
        high = len(_rows(
            client, "CrowdStrikeFalcon_CL | where ['event.Severity'] >= 70"))
        higher = len(_rows(
            client, "CrowdStrikeFalcon_CL | where ['event.Severity'] >= 100"))
        assert higher < high
        assert higher >= 1

    def test_in_and_its_negation_partition_the_table(
        self, client: TestClient,
    ) -> None:
        whole = len(_rows(client, "PaloAltoCortexXDR_CL"))
        inside = len(_rows(
            client,
            "PaloAltoCortexXDR_CL | where severity in ('high', 'critical')"))
        outside = len(_rows(
            client,
            "PaloAltoCortexXDR_CL | where severity !in ('high', 'critical')"))
        assert inside + outside == whole
        assert inside and outside

    def test_and_applies_both_halves(self, client: TestClient) -> None:
        one = len(_rows(
            client, "PaloAltoCortexXDR_CL | where severity == 'high'"))
        both = len(_rows(
            client,
            "PaloAltoCortexXDR_CL | where severity == 'high' and status == 'new'"))
        assert both < one

    def test_distinct_reduces_to_its_columns(self, client: TestClient) -> None:
        values = _rows(client, "SentinelOne_CL | distinct SourceSystem")
        assert all(len(row) == 1 for row in values)
        assert len(values) == len({tuple(row) for row in values})
        assert len(values) < len(_rows(client, "SentinelOne_CL"))

    def test_count_is_one_row(self, client: TestClient) -> None:
        assert _rows(client, "SentinelOne_CL | count") == [
            [len(_rows(client, "SentinelOne_CL"))]]


class TestWhatItCannotReadItRefuses:
    def test_an_unknown_operator(self, client: TestClient) -> None:
        assert "'mv-expand' operator is not supported" in _refusal(
            client, "SentinelOne_CL | mv-expand foo")

    def test_an_unreadable_predicate(self, client: TestClient) -> None:
        assert "cannot read the where clause" in _refusal(
            client, "SentinelOne_CL | where nonsense(((")

    def test_or_which_the_executor_cannot_express(
        self, client: TestClient,
    ) -> None:
        assert "'or' in a where clause is not supported" in _refusal(
            client, "SentinelOne_CL | where id == '1' or id == '2'")

    def test_the_missing_table_is_named_before_the_bad_pipeline(
        self, client: TestClient,
    ) -> None:
        """The more fundamental error, and the one a client can act on."""
        message = _refusal(client, "MicrosoftDefender_CL | mv-expand x")
        assert "MicrosoftDefender_CL" in message
        assert "mv-expand" not in message
