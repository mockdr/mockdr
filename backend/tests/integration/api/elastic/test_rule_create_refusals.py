"""What `POST /api/detection_engine/rules` requires, in 8.15's own words.

The console's own Create Rule button was answered `Invalid value
"undefined" supplied to "query"` every time it was pressed — a refusal the
product does not make. 8.15 accepts a `query` rule with no query at all and
stores `query: ""` with `language: "kuery"`; what it requires instead
depends on the type, and it words the refusal as zod does, naming every
missing member rather than the first.

Measured on 8.15, one body at a time:

    no name                 [request body]: name: Required
    no description          [request body]: description: Required
    no description, no severity
                            [request body]: description: Required, severity: Required
    type=query, no query    200, query stored as ""
    type=eql, no query      [request body]: query: Required
    type=threshold, no query
                            [request body]: query: Required, threshold: Required
    type=saved_query        [request body]: saved_id: Required
    type=saved_query + saved_id
                            200

The mock answered io-ts's wording for the first four, refused the fifth,
accepted the threshold rule it should refuse, and complained about the
wrong member for `saved_query`.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ES_AUTH = {
    "Authorization": "Basic ZWxhc3RpYzptb2NrLWVsYXN0aWMtcGFzc3dvcmQ=",
    "kbn-xsrf": "true",
}
RULES = "/kibana/api/detection_engine/rules"
_WHOLE = {"description": "d", "severity": "medium", "risk_score": 50,
          "type": "query", "enabled": False, "query": "*:*"}

#: (label, the body, the status 8.15 answers, the message it starts with)
MEASURED = [
    ("no name", {"description": "d", "severity": "medium", "risk_score": 50,
                 "type": "query", "query": "*:*"},
     400, "[request body]: name: Required"),
    ("no description", {"name": "p", "severity": "medium", "risk_score": 50,
                        "type": "query", "query": "*:*"},
     400, "[request body]: description: Required"),
    ("no description and no severity",
     {"name": "p", "risk_score": 50, "type": "query", "query": "*:*"},
     400, "[request body]: description: Required, severity: Required"),
    ("a query rule with no query",
     {"name": "p", "description": "d", "severity": "medium",
      "risk_score": 50, "type": "query"},
     200, ""),
    ("an eql rule with no query",
     {"name": "p", "description": "d", "severity": "medium",
      "risk_score": 50, "type": "eql"},
     400, "[request body]: query: Required"),
    ("a threshold rule with no query",
     {"name": "p", "description": "d", "severity": "medium",
      "risk_score": 50, "type": "threshold"},
     400, "[request body]: query: Required, threshold: Required"),
    ("a saved_query rule with no saved_id",
     {"name": "p", "description": "d", "severity": "medium",
      "risk_score": 50, "type": "saved_query"},
     400, "[request body]: saved_id: Required"),
    ("a saved_query rule with one",
     {"name": "p", "description": "d", "severity": "medium",
      "risk_score": 50, "type": "saved_query", "saved_id": "x"},
     200, ""),
]


@pytest.mark.parametrize(("label", "body", "status", "message"), MEASURED)
def test_the_mock_answers_what_the_product_answered(
    client: TestClient, label: str, body: dict, status: int, message: str,
) -> None:
    resp = client.post(RULES, headers=ES_AUTH, json={**body, "name": body.get("name", "")}
                       if "name" in body else body)
    assert resp.status_code == status, f"{label}: {resp.text}"
    if message:
        assert str(resp.json()["message"]).startswith(message), label


def test_a_query_rule_with_no_query_stores_an_empty_one(
    client: TestClient,
) -> None:
    """8.15 defaults it rather than refusing — that is the whole finding."""
    resp = client.post(RULES, headers=ES_AUTH, json={
        "name": "probe-defaults", "description": "d", "severity": "medium",
        "risk_score": 50, "type": "query"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["query"] == ""


def test_a_whole_rule_still_creates(client: TestClient) -> None:
    resp = client.post(RULES, headers=ES_AUTH, json={**_WHOLE, "name": "probe-whole"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["name"] == "probe-whole"
