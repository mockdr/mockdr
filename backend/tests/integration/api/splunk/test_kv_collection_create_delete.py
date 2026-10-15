"""Creating and deleting a KV Store collection answers what splunkd answers.

Measured on splunkd 10.4.2 via the conformance stack: ``POST
/servicesNS/nobody/search/storage/collections/config`` with ``name=…`` is
``201`` and the collections' feed around the one new entry — owned and
authored by the user who made it, removable, writable by admin and power,
with no ``fields`` block (a read by name adds one). A name already taken is
``409``. ``DELETE`` answers ``200`` and the feed with no entry at all; a name
there is none of is ``404 Could not find object id=<name>``. Both render as
Atom XML without ``output_mode=json``.

mockdr answered the create ``200 {"name": …}`` — and replaced an existing
collection, records included, with an empty one — and the delete with an INFO
message of its own wording.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import main
from tests.integration.api.test_review_fixes import SPLUNK_AUTH

BASE = "/splunk/servicesNS/nobody/search/storage/collections/config"
JSON = {"output_mode": "json"}


def _create(client: TestClient, name: str, **extra: str):
    return client.post(BASE, headers=SPLUNK_AUTH, params=JSON,
                       data={"name": name, **extra})


def test_create_is_201_and_the_feed_around_the_new_entry(client: TestClient) -> None:
    resp = _create(client, "conformance_kv_create")

    assert resp.status_code == 201
    body = resp.json()
    assert {"links", "origin", "updated", "generator", "entry", "paging",
            "messages"} <= set(body)
    assert body["paging"]["total"] == 1
    [entry] = body["entry"]
    assert entry["name"] == "conformance_kv_create"
    assert "fields" not in entry
    assert entry["author"] == "admin"
    assert entry["acl"]["owner"] == "admin"
    assert entry["acl"]["app"] == "search"
    assert entry["acl"]["sharing"] == "app"
    assert entry["acl"]["removable"] is True
    assert entry["acl"]["can_share_user"] is True
    assert entry["acl"]["perms"] == {"read": ["*"], "write": ["admin", "power"]}
    assert set(entry["links"]) == {
        "alternate", "list", "_reload", "edit", "remove", "disable"}
    content = entry["content"]
    assert content["type"] == "undefined"
    assert content["eai:appName"] == "search"
    assert content["eai:userName"] == "nobody"
    assert content["replicate"] == "false"


def test_the_schema_given_at_creation_is_reported_back(client: TestClient) -> None:
    content = _create(
        client, "conformance_kv_schema",
        **{"field.host": "string", "accelerated_fields.a": '{"host":1}'},
    ).json()["entry"][0]["content"]

    assert content["field.host"] == "string"
    assert content["accelerated_fields.a"] == '{"host":1}'


def test_a_name_already_taken_is_409_and_the_records_stay(client: TestClient) -> None:
    _create(client, "conformance_kv_dup")
    client.post("/splunk/servicesNS/nobody/search/storage/collections/data/"
                "conformance_kv_dup", headers=SPLUNK_AUTH, json={"_key": "k1"})

    again = _create(client, "conformance_kv_dup")

    assert again.status_code == 409
    assert again.json()["messages"] == [{
        "type": "ERROR",
        "text": "An object with name=conformance_kv_dup already exists",
    }]
    records = client.get(
        "/splunk/servicesNS/nobody/search/storage/collections/data/conformance_kv_dup",
        headers=SPLUNK_AUTH,
    ).json()
    assert [r["_key"] for r in records] == ["k1"]


def test_delete_answers_the_feed_with_no_entry(client: TestClient) -> None:
    _create(client, "conformance_kv_delete")

    resp = client.delete(f"{BASE}/conformance_kv_delete", headers=SPLUNK_AUTH, params=JSON)

    assert resp.status_code == 200
    body = resp.json()
    assert body["entry"] == []
    assert body["paging"]["total"] == 0
    assert set(body["links"]) == {"create", "_reload", "_acl"}
    assert {"origin", "updated", "generator", "messages"} <= set(body)


def test_deleting_a_name_there_is_none_of_is_404(client: TestClient) -> None:
    resp = client.delete(f"{BASE}/conformance_kv_none", headers=SPLUNK_AUTH, params=JSON)

    assert resp.status_code == 404
    assert resp.json()["messages"][0]["text"] == "Could not find object id=conformance_kv_none"


@pytest.fixture()
def raw_client(fresh_seed: None) -> TestClient:
    """A client that does not ask for JSON, as the package's fixture does."""
    return TestClient(main.app)


def test_without_output_mode_both_answer_atom(raw_client: TestClient) -> None:
    created = raw_client.post(BASE, headers=SPLUNK_AUTH, data={"name": "conformance_kv_xml"})
    deleted = raw_client.delete(f"{BASE}/conformance_kv_xml", headers=SPLUNK_AUTH)

    assert created.status_code == 201
    assert created.headers["content-type"].startswith("text/xml")
    assert "<title>conformance_kv_xml</title>" in created.text
    assert deleted.status_code == 200
    assert "<opensearch:totalResults>0</opensearch:totalResults>" in deleted.text
    assert "<entry>" not in deleted.text
