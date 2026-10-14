"""A KV collection's configuration entry names the app its data is served from.

Every entry of ``storage/collections/config`` claimed the system namespace --
``acl.app: system``, ``id: .../servicesNS/nobody/system/...`` -- while the
collection's records were served only under the app it was defined in
(``search`` for ``splunk_xsoar_users``). A client that takes the namespace
from the entry, as splunklib's ``Entity.path`` does, asked for the data under
``system`` and got a 404. splunkd's REST reference shows a collection of the
search app at ``/servicesNS/nobody/search/storage/collections/config/<name>``
with ``eai:appName: search``, and a recorded 6.4 response gives its ACL as
``app: search``, ``sharing: app``.
"""
from __future__ import annotations

import base64
from urllib.parse import urlsplit

from fastapi.testclient import TestClient

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}


def _entries(client: TestClient, app: str) -> list[dict]:
    resp = client.get(f"/splunk/servicesNS/nobody/{app}/storage/collections/config",
                      params={"output_mode": "json"}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    return list(resp.json()["entry"])


def test_the_entry_names_the_collections_own_app(client: TestClient) -> None:
    (entry,) = [e for e in _entries(client, "search") if e["name"] == "splunk_xsoar_users"]
    assert entry["acl"]["app"] == "search"
    assert entry["acl"]["sharing"] == "app"
    assert entry["content"]["eai:appName"] == "search"
    assert "/servicesNS/nobody/search/storage/collections/config/" in entry["id"]


def test_the_data_is_where_the_entry_says(client: TestClient) -> None:
    for app in ("search", "SA-ThreatIntelligence"):
        for entry in _entries(client, app):
            owner, namespace = urlsplit(entry["id"]).path.split("/")[2:4]
            assert namespace == entry["acl"]["app"] == app
            resp = client.get(
                f"/splunk/servicesNS/{owner}/{namespace}/storage/collections/data/"
                f"{entry['name']}", params={"output_mode": "json"}, headers=AUTH,
            )
            assert resp.status_code == 200, (entry["name"], resp.text[:200])
