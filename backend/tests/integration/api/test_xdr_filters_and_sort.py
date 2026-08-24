"""Cortex XDR answers the filters and the order its integrations ask for.

The XSOAR Cortex XDR pack sends a ``sort`` block on every fetch and filters
incidents by ``incident_id_list``, ``status``, ``starred`` and time. The mock
matched three fields with a hand-written chain, ignored the rest without
saying so, and never sorted at all — a client paging by modification time
received the mock's own order.
"""

from __future__ import annotations

import hashlib
import secrets
import time

from fastapi.testclient import TestClient

PREFIX = "/xdr/public_api/v1"


def _auth() -> dict[str, str]:
    nonce = secrets.token_hex(32)
    stamp = str(int(time.time() * 1000))
    digest = hashlib.sha256(("xdr-admin-secret" + nonce + stamp).encode()).hexdigest()
    return {
        "x-xdr-auth-id": "1",
        "x-xdr-nonce": nonce,
        "x-xdr-timestamp": stamp,
        "Authorization": digest,
    }


def _incidents(client: TestClient, **request_data: object) -> list[dict]:
    response = client.post(
        f"{PREFIX}/incidents/get_incidents/", headers=_auth(), json={"request_data": request_data}
    )
    assert response.status_code == 200, response.text
    return response.json()["reply"]["incidents"]


class TestIncidentFilters:
    def test_incident_id_list_returns_only_that_incident(self, client: TestClient) -> None:
        everything = _incidents(client)
        wanted = everything[0]["incident_id"]
        narrowed = _incidents(
            client, filters=[{"field": "incident_id_list", "operator": "in", "value": [wanted]}]
        )
        assert [i["incident_id"] for i in narrowed] == [wanted]

    def test_starred_is_a_property_of_the_incident(self, client: TestClient) -> None:
        everything = _incidents(client)
        assert len({i["starred"] for i in everything}) == 2, "every incident has the same star"
        starred = _incidents(
            client, filters=[{"field": "starred", "operator": "eq", "value": True}]
        )
        assert starred and all(i["starred"] for i in starred)

    def test_an_undeclared_filter_field_is_refused(self, client: TestClient) -> None:
        response = client.post(
            f"{PREFIX}/incidents/get_incidents/",
            headers=_auth(),
            json={"request_data": {"filters": [{"field": "nonesuch", "operator": "eq",
                                                "value": "x"}]}},
        )
        assert response.status_code == 400


class TestSorting:
    def test_incidents_sort_ascending_and_descending(self, client: TestClient) -> None:
        ascending = [
            i["creation_time"]
            for i in _incidents(client, sort={"field": "creation_time", "keyword": "asc"})
        ]
        assert ascending == sorted(ascending)

        descending = [
            i["modification_time"]
            for i in _incidents(client, sort={"field": "modification_time", "keyword": "desc"})
        ]
        assert descending == sorted(descending, reverse=True)

    def test_endpoints_and_alerts_sort_too(self, client: TestClient) -> None:
        for route, key, field in [
            ("endpoints/get_endpoint/", "endpoints", "endpoint_name"),
            ("alerts/get_alerts_by_filter_data/", "alerts", "severity"),
        ]:
            response = client.post(
                f"{PREFIX}/{route}",
                headers=_auth(),
                json={"request_data": {"sort": {"field": field, "keyword": "asc"}}},
            )
            assert response.status_code == 200, response.text
            values = [str(r.get(field, "")) for r in response.json()["reply"][key]]
            assert values == sorted(values), f"{route} ignored sort by {field}"
