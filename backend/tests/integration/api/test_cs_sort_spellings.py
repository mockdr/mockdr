"""Falcon's ``field|direction`` sort orders the answer.

gofalcon documents the pipe form for alerts ("Sort parameter takes the form
<field|direction> ... For example: `status|asc`", query_v2_parameters.go),
cases, quarantine ("Ex: 'date_created|asc'") and users (``Default:
"uid|asc"``), and falconpy discussion #536 scrolls hosts with
``sort="hostname|asc"``. Every parser on this mount split on the last ``.``,
so the pipe form was read as a field called ``hostname|asc`` that no record
has: the answer came back in storage order with a 200, and a client that
pages "newest first" got pages in no order at all. The dot form gofalcon
documents for hosts ("e.g. status.desc or hostname.asc") keeps working.

A dotted field with no direction lost its last segment too:
``value``-style IOC sorts such as ``metadata.av_hits`` (falconpy's enum for
``indicator_combined_v1``) were read as field ``metadata``, direction
``av_hits``.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from utils.cs_sort import parse_cs_sort


def _cs_auth(client: TestClient) -> dict[str, str]:
    resp = client.post("/cs/oauth2/token", data={
        "client_id": "cs-mock-admin-client",
        "client_secret": "cs-mock-admin-secret",
    })
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class TestParseCsSort:
    """Both documented spellings, and a nested field, parse."""

    @pytest.mark.parametrize(("sort", "expected"), [
        ("status|asc", ("status", False)),
        ("status|desc", ("status", True)),
        ("hostname.asc", ("hostname", False)),
        ("hostname.desc", ("hostname", True)),
        ("device.hostname|desc", ("device.hostname", True)),
        ("metadata.av_hits", ("metadata.av_hits", False)),
        ("modified_on", ("modified_on", False)),
        (None, ("last_seen", True)),
    ])
    def test_spelling(self, sort: str | None, expected: tuple[str, bool]) -> None:
        assert parse_cs_sort(sort, "last_seen", True) == expected


def _hostnames(client: TestClient, headers: dict, sort: str) -> list[str]:
    ids = client.get("/cs/devices/queries/devices/v1", headers=headers,
                     params={"limit": 100, "sort": sort}).json()["resources"]
    by_id = {
        h["device_id"]: h["hostname"]
        for h in client.post("/cs/devices/entities/devices/v2", headers=headers,
                             json={"ids": ids}).json()["resources"]
    }
    return [by_id[i] for i in ids]


class TestPipeSortOrders:
    """The pipe spelling sorts, in the direction it names."""

    @pytest.mark.parametrize("sort", ["hostname|asc", "hostname.asc"])
    def test_hosts_ascending(self, client: TestClient, sort: str) -> None:
        names = _hostnames(client, _cs_auth(client), sort)
        assert names == sorted(names)

    @pytest.mark.parametrize("sort", ["hostname|desc", "hostname.desc"])
    def test_hosts_descending(self, client: TestClient, sort: str) -> None:
        names = _hostnames(client, _cs_auth(client), sort)
        assert names == sorted(names, reverse=True)

    def test_iocs_by_value(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        values = [r["value"] for r in client.get(
            "/cs/iocs/combined/indicator/v1", headers=headers,
            params={"limit": 500, "sort": "value|asc"}).json()["resources"]]
        assert len(values) > 2
        assert values == sorted(values)

    def test_host_groups_by_name_descending(self, client: TestClient) -> None:
        headers = _cs_auth(client)
        names = [g["name"] for g in client.get(
            "/cs/devices/combined/host-groups/v1", headers=headers,
            params={"sort": "name|desc"}).json()["resources"]]
        assert len(names) > 1
        assert names == sorted(names, reverse=True)

    def test_users_by_uid(self, client: TestClient) -> None:
        """``uid|asc`` is gofalcon's documented default spelling for users."""
        headers = _cs_auth(client)
        ids = client.get("/cs/user-management/queries/users/v1", headers=headers,
                         params={"sort": "uid|asc"}).json()["resources"]
        users = client.post("/cs/user-management/entities/users/GET/v1", headers=headers,
                            json={"ids": ids}).json()["resources"]
        uid_by_uuid = {u["uuid"]: u["uid"] for u in users}
        uids = [uid_by_uuid[i] for i in ids]
        assert len(uids) > 1
        assert uids == sorted(uids)
