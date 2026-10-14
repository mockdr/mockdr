"""A Cortex alert's internal_id is an integer, as Cortex answers it.

XSOAR's recorded replies carry `"internal_id": 33333`
(CortexXDRIR/test_data/get_alerts_by_filter_results.json, and the
CoreIRApiModule copy) and `"internal_id": 333`
(get_original_alerts_results.json), and its tests assert
`outputs[0]["internal_id"] == 33333`. The seed wrote `"INT_3fa9…"`, which a
client typing the field as a number cannot read, and an inserted alert
answered `""`.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from application.dev.migrations import migrate_record
from repository.xdr_alert_repo import xdr_alert_repo

BASE = "/xdr/public_api/v1"


@pytest.fixture()
def xdr() -> dict[str, str]:
    return {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}


def test_every_seeded_alert_has_a_distinct_integer() -> None:
    ids = [a.internal_id for a in xdr_alert_repo.list_all()]
    assert ids and all(type(i) is int and 0 < i < 2**53 for i in ids)
    assert len(set(ids)) == len(ids)


def test_the_filter_data_and_original_alert_routes_answer_integers(
    client: TestClient, xdr: dict[str, str],
) -> None:
    page = client.post(f"{BASE}/alerts/get_alerts_by_filter_data", headers=xdr, json={
        "request_data": {"paging": {"from": 0, "to": 5}},
    }).json()["reply"]["alerts"]
    assert page and all(type(a["alert_fields"]["internal_id"]) is int for a in page)
    alert_id = xdr_alert_repo.list_all()[0].alert_id
    rows = client.post(f"{BASE}/alerts/get_original_alerts", headers=xdr, json={
        "request_data": {"alert_id_list": [alert_id]},
    }).json()["reply"]["alerts"]
    assert type(rows[0]["internal_id"]) is int


def test_an_inserted_alert_gets_the_next_integer(client: TestClient, xdr: dict[str, str]) -> None:
    highest = max(a.internal_id for a in xdr_alert_repo.list_all())
    resp = client.post(f"{BASE}/alerts/insert_parsed_alerts", headers=xdr, json={
        "request_data": {"alerts": [{"alert_id": "ext-1", "product": "p", "vendor": "v",
                                     "local_ip": "192.0.2.1", "local_port": 1,
                                     "remote_ip": "192.0.2.2", "remote_port": 2,
                                     "event_timestamp": 1, "severity": "Low",
                                     "alert_name": "n", "alert_description": "d"}]},
    })
    assert resp.status_code == 200, resp.text
    assert xdr_alert_repo.get("ext-1").internal_id == highest + 1


def test_a_snapshot_from_before_reads_as_an_integer() -> None:
    record = {"alert_id": "a", "internal_id": "INT_00000ff123456789"}
    assert migrate_record("xdr_alerts", record)
    assert record["internal_id"] == 0xFF  # its first seven hex digits, as the seed now derives it
    current = {"alert_id": "a", "internal_id": 4081}
    assert not migrate_record("xdr_alerts", current)
