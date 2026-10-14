"""An unset Defender date is null, as Defender sends it -- never "".

The docs-generated defaults wrote "" for every property the record did not
set, dates included: a pending machine action answered
`"cancellationDateTimeUtc": ""`, an investigation still running
`"endTime": ""`. Defender's own examples answer null (`"endTime": null`,
`"resolvedTime": null`, `"cancellationDateTimeUtc": null`), and "" is a value
no date parser reads -- the defect that made azure-mgmt-securityinsight
refuse whole Sentinel pages.
"""
from __future__ import annotations

import re

from fastapi.testclient import TestClient

_DATE = re.compile(r"(?:Time|DateTimeUtc|Seen|Observed|On|Detected)$")


def _token(client: TestClient) -> dict[str, str]:
    token = client.post("/mde/oauth2/v2.0/token", data={
        "client_id": "mde-mock-admin-client", "client_secret": "mde-mock-admin-secret",
        "grant_type": "client_credentials",
        "scope": "https://api.securitycenter.microsoft.com/.default",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _blank_dates(obj: object, path: str = "") -> list[str]:
    if isinstance(obj, dict):
        return [p for k, v in obj.items() for p in _blank_dates(v, f"{path}.{k}")
                if p] + [f"{path}.{k}" for k, v in obj.items()
                         if v == "" and _DATE.search(k)]
    if isinstance(obj, list):
        return [p for item in obj for p in _blank_dates(item, f"{path}[]")]
    return []


def test_a_pending_machine_action_has_no_cancellation_date(client: TestClient) -> None:
    headers = _token(client)
    machine = client.get("/mde/api/machines", headers=headers).json()["value"][0]
    resp = client.post(f"/mde/api/machines/{machine['id']}/runAntiVirusScan", headers=headers,
                       json={"Comment": "scan", "ScanType": "Quick"})
    assert resp.status_code in (200, 201), resp.text
    action = resp.json()
    assert action["cancellationDateTimeUtc"] is None
    assert action["creationDateTimeUtc"]


def test_no_collection_answers_an_empty_date(client: TestClient) -> None:
    headers = _token(client)
    blanks = []
    for path in ("machines", "alerts", "machineactions", "investigations", "indicators",
                 "vulnerabilities", "software"):
        body = client.get(f"/mde/api/{path}", headers=headers).json()
        blanks += [f"{path}{p}" for p in _blank_dates(body.get("value", []))]
    assert not blanks, sorted(set(blanks))[:20]
