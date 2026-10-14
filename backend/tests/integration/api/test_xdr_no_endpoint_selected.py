"""An endpoint action whose filters select nobody says so, in Cortex's words.

`run_script` answered `500 Script <uid> not found` when the script existed and
the filters matched no endpoint -- naming the one thing that was there. The
endpoint actions answered `Endpoint  not found` with an empty name. Cortex
answers a 500 whose message XSOAR's CoreIRApiModule matches to report "The
operation executed is not supported on the given machine."
(`catch_and_exit_gracefully`, mocked in its tests as `GRACEFULLY_FAILING`).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from utils.xdr_response import XDR_ERR_NO_ENDPOINT

BASE = "/xdr/public_api/v1"
NOBODY = [{"field": "endpoint_id_list", "operator": "in", "value": ["no-such-endpoint"]}]


@pytest.fixture()
def xdr() -> dict[str, str]:
    return {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}


def _a_script(client: TestClient, xdr: dict[str, str]) -> str:
    scripts = client.post(f"{BASE}/scripts/get_scripts/", headers=xdr,
                          json={"request_data": {}}).json()["reply"]["scripts"]
    return str(scripts[0]["script_uid"])


def test_a_script_run_on_nobody_is_not_a_missing_script(
    client: TestClient, xdr: dict[str, str],
) -> None:
    resp = client.post(f"{BASE}/scripts/run_script/", headers=xdr, json={"request_data": {
        "script_uid": _a_script(client, xdr), "filters": NOBODY,
    }})
    assert resp.status_code == 500
    reply = resp.json()["reply"]
    assert reply["err_code"] == 500
    assert "no endpoint was found for creating the requested action" in reply["err_msg"].lower()
    assert reply["err_msg"] == XDR_ERR_NO_ENDPOINT


def test_a_missing_script_is_still_a_missing_script(
    client: TestClient, xdr: dict[str, str],
) -> None:
    resp = client.post(f"{BASE}/scripts/run_script/", headers=xdr, json={"request_data": {
        "script_uid": "no-such-script", "filters": NOBODY,
    }})
    assert resp.status_code == 500
    assert "no-such-script" in str(resp.json()["reply"]["err_extra"])


@pytest.mark.parametrize("path", ["endpoints/isolate", "endpoints/unisolate",
                                  "endpoints/scan/"])
def test_an_action_on_nobody_says_no_endpoint_was_found(
    client: TestClient, xdr: dict[str, str], path: str,
) -> None:
    resp = client.post(f"{BASE}/{path}", headers=xdr, json={"request_data": {
        "filters": NOBODY,
    }})
    assert resp.status_code == 500
    assert resp.json()["reply"]["err_msg"] == XDR_ERR_NO_ENDPOINT
