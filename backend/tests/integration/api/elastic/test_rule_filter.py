"""`rules/_find?filter=` is a saved-object query, not a text search.

It read `enabled` by looking for that word anywhere in the string and turned
everything else into a substring search over rule names and tags. So
`alert.attributes.params.severity: critical` — which is exactly what the
console's own severity dropdown sends — matched no rule name, returned an
empty page, and the table went blank for every severity a person picked.

Measured on 8.15 against nine of its own rules:

    alert.attributes.params.severity: medium            7 of 9
    alert.attributes.params.severity: low               2 of 9
    alert.attributes.name: *                            9
    alert.attributes.params.risk_score >= 50            7
    enabled: true AND params.severity: medium           3
    alert.attributes.nonsense: x                        400, "This key … does
                                                        NOT exist in alert
                                                        saved object index
                                                        patterns: Bad Request"
    just some words                                     400, "The key is empty
                                                        and needs to be wrapped
                                                        by a saved object type
                                                        like alert: Bad Request"

An unknown attribute is refused rather than answered with an empty page,
which is the difference between "there are none" and "you asked wrongly".
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ES_AUTH = {"Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ="}
FIND = "/kibana/api/detection_engine/rules/_find"


def _rules(client: TestClient, **params: object) -> list[dict]:
    resp = client.get(FIND, headers=ES_AUTH, params={"per_page": 100, **params})
    assert resp.status_code == 200, resp.text
    return list(resp.json()["data"])


class TestTheFilterSelects:
    def test_the_severities_partition_the_rules(self, client: TestClient) -> None:
        everything = _rules(client)
        counted = 0
        for severity in ("critical", "high", "medium", "low"):
            picked = _rules(
                client, filter=f"alert.attributes.params.severity: {severity}")
            assert all(r["severity"] == severity for r in picked), severity
            counted += len(picked)
        assert counted == len(everything)

    def test_enabled_still_selects(self, client: TestClient) -> None:
        on = _rules(client, filter="alert.attributes.enabled: true")
        off = _rules(client, filter="alert.attributes.enabled: false")
        assert all(r["enabled"] for r in on)
        assert not any(r["enabled"] for r in off)
        assert len(on) + len(off) == len(_rules(client))

    def test_two_clauses_narrow_further(self, client: TestClient) -> None:
        one = _rules(client, filter="alert.attributes.params.severity: high")
        both = _rules(client, filter=(
            "alert.attributes.enabled: true AND "
            "alert.attributes.params.severity: high"))
        assert len(both) <= len(one)
        assert all(r["enabled"] and r["severity"] == "high" for r in both)

    def test_a_wildcard_takes_everything_that_has_the_field(
        self, client: TestClient,
    ) -> None:
        assert len(_rules(client, filter="alert.attributes.name: *")) == len(
            _rules(client))

    def test_a_range_compares_numbers(self, client: TestClient) -> None:
        above = _rules(client, filter="alert.attributes.params.risk_score >= 50")
        assert above
        assert all(r["risk_score"] >= 50 for r in above)


class TestWhatItRefuses:
    @pytest.mark.parametrize(("expression", "message"), [
        ("alert.attributes.nonsense: x",
         "This key 'alert.attributes.nonsense' does NOT exist in alert saved "
         "object index patterns: Bad Request"),
        ("just some words",
         "The key is empty and needs to be wrapped by a saved object type "
         "like alert: Bad Request"),
    ])
    def test_it_says_so_rather_than_answering_an_empty_page(
        self, client: TestClient, expression: str, message: str,
    ) -> None:
        resp = client.get(FIND, headers=ES_AUTH, params={"filter": expression})
        assert resp.status_code == 400, resp.text
        assert resp.json()["message"] == message
