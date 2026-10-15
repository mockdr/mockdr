"""A lookup definition's entry reports what splunkd reports for it.

Measured on splunkd 10.4.2 via the conformance stack, creating definitions
over ``POST /servicesNS/nobody/search/data/transforms/lookups`` and reading
them back:

- a kvstore definition is ``type: kvstore`` — mockdr said ``external``, which
  is the type of a scripted lookup;
- without ``fields_list`` it reports ``fields_list: null`` and
  ``fields_array: []``; a file definition lists its CSV header in both;
- each optional setting given comes back as splunkd keeps it —
  ``case_sensitive_match`` and ``default_match`` as the text given,
  ``max_matches`` and ``min_matches`` as integers — and one not given is
  absent, defaults included;
- the definition is its creator's: author and ACL owner are the requesting
  user (``eai:userName`` stays the namespace's ``nobody``), removable,
  re-shareable to user level, writable by admin and power;
- a read by name carries a ``fields`` block listing the settings the stanza
  accepts; the create answer does not.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from infrastructure.seeders.splunk.lookup_seeder import _ASSET_HEADER
from tests.integration.api.test_review_fixes import SPLUNK_AUTH

TRANSFORMS = "/splunk/servicesNS/nobody/search/data/transforms/lookups"
KV_CONFIG = "/splunk/servicesNS/nobody/search/storage/collections/config"
JSON = {"output_mode": "json"}


def _define(client: TestClient, **params: str) -> dict:
    client.post(KV_CONFIG, headers=SPLUNK_AUTH, params=JSON, data={"name": "probe_coll"})
    resp = client.post(TRANSFORMS, headers=SPLUNK_AUTH, params=JSON, data=params)
    assert resp.status_code == 201
    return resp.json()["entry"][0]


def test_a_kvstore_definition_is_type_kvstore(client: TestClient) -> None:
    entry = _define(client, name="probe_lk", external_type="kvstore",
                    collection="probe_coll", fields_list="_key,host,owner")

    content = entry["content"]
    assert content["type"] == "kvstore"
    assert content["external_type"] == "kvstore"
    assert content["fields_array"] == ["_key", "host", "owner"]
    assert content["fields_list"] == "_key,host,owner"
    for unset in ("case_sensitive_match", "max_matches", "min_matches", "default_match"):
        assert unset not in content
    assert "fields" not in entry


def test_it_is_the_creators(client: TestClient) -> None:
    entry = _define(client, name="probe_lk", collection="probe_coll")

    assert entry["author"] == "admin"
    assert entry["content"]["eai:userName"] == "nobody"
    acl = entry["acl"]
    assert (acl["owner"], acl["app"], acl["sharing"]) == ("admin", "search", "global")
    assert acl["removable"] is True
    assert acl["can_share_user"] is True
    assert acl["perms"] == {"read": ["*"], "write": ["admin", "power"]}


def test_only_a_created_one_can_be_moved_or_removed(client: TestClient) -> None:
    created = _define(client, name="probe_lk", collection="probe_coll")
    shipped = client.get(f"{TRANSFORMS}/ip_intel", headers=SPLUNK_AUTH,
                         params=JSON).json()["entry"][0]

    assert set(created["links"]) == {
        "_reload", "alternate", "disable", "edit", "list", "move", "remove"}
    assert set(shipped["links"]) == {"_reload", "alternate", "disable", "edit", "list"}


def test_without_fields_list_it_is_null(client: TestClient) -> None:
    content = _define(client, name="probe_lk", collection="probe_coll")["content"]

    assert content["fields_list"] is None
    assert content["fields_array"] == []


def test_the_settings_given_come_back_as_splunkd_keeps_them(client: TestClient) -> None:
    content = _define(
        client, name="probe_lk", collection="probe_coll", case_sensitive_match="false",
        max_matches="5", min_matches="1", default_match="none",
    )["content"]

    assert content["case_sensitive_match"] == "false"
    assert content["max_matches"] == 5
    assert content["min_matches"] == 1
    assert content["default_match"] == "none"


def test_a_file_definition_lists_its_header(client: TestClient) -> None:
    content = client.get(f"{TRANSFORMS}/mockdr_assets", headers=SPLUNK_AUTH,
                         params=JSON).json()["entry"][0]["content"]

    assert content["type"] == "file"
    assert content["fields_array"] == list(_ASSET_HEADER)
    assert content["fields_list"] == ",".join(_ASSET_HEADER)


def test_a_read_by_name_names_what_the_stanza_accepts(client: TestClient) -> None:
    _define(client, name="probe_lk", collection="probe_coll")

    entry = client.get(f"{TRANSFORMS}/probe_lk", headers=SPLUNK_AUTH,
                       params=JSON).json()["entry"][0]

    assert entry["fields"]["required"] == []
    assert entry["fields"]["wildcard"] == []
    optional = entry["fields"]["optional"]
    assert len(optional) == 26
    assert {"collection", "external_type", "fields_list", "filename",
            "max_matches", "case_sensitive_match"} <= set(optional)
