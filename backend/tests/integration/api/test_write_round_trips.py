"""What a write leaves behind, and what the answer to it says.

Every case here comes from ``scripts/roundtrip_audit.py`` — the audit that
writes something and then asks the mock to hand it back. A mock can answer
each single request plausibly and still forget what it was told: a create
that drops half the body, an update that answers 200 and changes nothing, a
delete that answers 200 and leaves the record where it was. All three are
200s, and a client that never re-reads never sees them.

The Splunk and Kibana expectations are measured — Splunk 10.4.2 and Kibana
8.15, through ``conformance/``. The rest come from each vendor's published
request schema, cited where it is not obvious.
"""

from __future__ import annotations

import base64
import json
import re
import time

import pytest
from fastapi.testclient import TestClient

from application.cs_hosts import queries as host_queries
from application.es_endpoints import commands as endpoint_commands

SPLUNK_AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
FORM = {"Content-Type": "application/x-www-form-urlencoded", **SPLUNK_AUTH}
JSON_OUT = {"output_mode": "json"}


@pytest.fixture
def cs_headers(client: TestClient) -> dict:
    token = client.post("/cs/oauth2/token", data={
        "grant_type": "client_credentials",
        "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
    }).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def xdr_headers() -> dict:
    return {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}


class TestFalconHostGroupsTakeACollection:
    """``HostGroupsCreateGroupsReqV1`` is a list, and both members are required."""

    def test_create_makes_every_group_in_resources(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        resp = client.post("/cs/devices/entities/host-groups/v1", headers=cs_headers, json={
            "resources": [
                {"name": "zzz-one", "group_type": "static"},
                {"name": "zzz-two", "group_type": "static", "description": "second"},
            ],
        })
        assert resp.status_code == 200
        made = resp.json()["resources"]
        assert [g["name"] for g in made] == ["zzz-one", "zzz-two"]
        assert made[1]["description"] == "second"

    def test_create_without_resources_is_refused(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        resp = client.post("/cs/devices/entities/host-groups/v1", headers=cs_headers,
                           json={"name": "flat", "group_type": "static"})
        assert resp.status_code == 400
        assert resp.json()["errors"][0]["code"] == 400

    @pytest.mark.parametrize("missing", ["name", "group_type"])
    def test_create_needs_both_required_members(
        self, client: TestClient, cs_headers: dict, missing: str,
    ) -> None:
        group = {"name": "zzz-x", "group_type": "static"}
        del group[missing]
        resp = client.post("/cs/devices/entities/host-groups/v1", headers=cs_headers,
                           json={"resources": [group]})
        assert resp.status_code == 400
        assert missing in resp.json()["errors"][0]["message"]

    def test_update_changes_every_group_named(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        made = client.post("/cs/devices/entities/host-groups/v1", headers=cs_headers, json={
            "resources": [{"name": "zzz-a", "group_type": "static"},
                          {"name": "zzz-b", "group_type": "static"}],
        }).json()["resources"]
        ids = [g["id"] for g in made]

        resp = client.patch("/cs/devices/entities/host-groups/v1", headers=cs_headers, json={
            "resources": [{"id": ids[0], "description": "first"},
                          {"id": ids[1], "description": "second"}],
        })
        assert resp.status_code == 200
        read = client.get("/cs/devices/entities/host-groups/v1", headers=cs_headers,
                          params={"ids": ",".join(ids)}).json()["resources"]
        assert [g["description"] for g in read] == ["first", "second"]

    def test_queries_route_answers_the_ids(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        """``QueryHostGroups`` — the ID half of a pair the mock only had half of."""
        resp = client.get("/cs/devices/queries/host-groups/v1", headers=cs_headers)
        assert resp.status_code == 200
        ids = resp.json()["resources"]
        assert ids and all(isinstance(i, str) for i in ids)

    def test_group_member_queries_route_answers_device_ids(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        group = client.get("/cs/devices/queries/host-groups/v1",
                           headers=cs_headers).json()["resources"][0]
        combined = client.get("/cs/devices/combined/host-group-members/v1",
                              headers=cs_headers, params={"id": group}).json()["resources"]
        resp = client.get("/cs/devices/queries/host-group-members/v1", headers=cs_headers,
                          params={"id": group})
        assert resp.status_code == 200
        assert resp.json()["resources"] == [h["device_id"] for h in combined]


class TestFalconIocUpdateIsAList:
    """``APIIndicatorUpdateReqsV1.indicators`` is a list, and all of it counts."""

    def test_update_changes_every_indicator_named(
        self, client: TestClient, cs_headers: dict,
    ) -> None:
        made = client.post("/cs/iocs/entities/indicators/v1", headers=cs_headers, json={
            "indicators": [
                {"type": "domain", "value": "zzz-one.test", "action": "no_action"},
                {"type": "domain", "value": "zzz-two.test", "action": "no_action"},
            ],
        }).json()["resources"]
        ids = [i["id"] for i in made]

        client.patch("/cs/iocs/entities/indicators/v1", headers=cs_headers, json={
            "indicators": [{"id": ids[0], "description": "first"},
                           {"id": ids[1], "description": "second"}],
        })
        read = client.get("/cs/iocs/entities/indicators/v1", headers=cs_headers,
                          params={"ids": ",".join(ids)}).json()["resources"]
        assert [i["description"] for i in read] == ["first", "second"]


class TestCortexEndpointFilters:
    """Every filter field Cortex publishes, not the four that were read by hand."""

    def _endpoint(self, client: TestClient, headers: dict) -> dict:
        return client.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=headers,
                           json={"request_data": {"search_from": 0, "search_to": 1}},
                           ).json()["reply"]["endpoints"][0]

    def test_endpoint_id_list_narrows(self, client: TestClient, xdr_headers: dict) -> None:
        endpoint = self._endpoint(client, xdr_headers)
        resp = client.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=xdr_headers,
                           json={"request_data": {"filters": [
                               {"field": "endpoint_id_list", "operator": "in",
                                "value": [endpoint["endpoint_id"]]},
                           ]}})
        assert resp.json()["reply"]["total_count"] == 1

    def test_a_filter_that_matches_nothing_answers_nothing(
        self, client: TestClient, xdr_headers: dict,
    ) -> None:
        resp = client.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=xdr_headers,
                           json={"request_data": {"filters": [
                               {"field": "endpoint_id_list", "operator": "in",
                                "value": ["no-such-endpoint"]},
                           ]}})
        assert resp.json()["reply"]["total_count"] == 0

    def test_an_unsupported_field_is_refused(
        self, client: TestClient, xdr_headers: dict,
    ) -> None:
        """Cortex names the field rather than answering the whole estate."""
        resp = client.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=xdr_headers,
                           json={"request_data": {"filters": [
                               {"field": "zzz_not_a_field", "operator": "in", "value": ["x"]},
                           ]}})
        assert resp.status_code == 400

    def test_update_agent_name_takes_filters(
        self, client: TestClient, xdr_headers: dict,
    ) -> None:
        endpoint = self._endpoint(client, xdr_headers)
        where = [{"field": "endpoint_id_list", "operator": "in",
                  "value": [endpoint["endpoint_id"]]}]
        resp = client.post("/xdr/public_api/v1/endpoints/update_agent_name/",
                           headers=xdr_headers,
                           json={"request_data": {"filters": where, "alias": "zzz-alias"}})
        assert resp.status_code == 200
        after = client.post("/xdr/public_api/v1/endpoints/get_endpoint/", headers=xdr_headers,
                            json={"request_data": {"filters": where}})
        assert after.json()["reply"]["endpoints"][0]["alias"] == "zzz-alias"


class TestCortexIncidentOverrides:
    """``update_data`` carries the analyst's overrides, ``manual_severity`` included."""

    def test_manual_severity_reads_back(self, client: TestClient, xdr_headers: dict) -> None:
        incident = client.post("/xdr/public_api/v1/incidents/get_incidents/",
                               headers=xdr_headers,
                               json={"request_data": {"search_from": 0, "search_to": 1}},
                               ).json()["reply"]["incidents"][0]
        incident_id = str(incident["incident_id"])
        client.post("/xdr/public_api/v1/incidents/update_incident/", headers=xdr_headers,
                    json={"request_data": {"incident_id": incident_id, "update_data": {
                        "manual_severity": "high", "resolve_comment": "zzz",
                        "status": "under_investigation",
                    }}})
        after = client.post("/xdr/public_api/v1/incidents/get_incident_extra_data/",
                            headers=xdr_headers,
                            json={"request_data": {"incident_id": incident_id}},
                            ).json()["reply"]["incident"]
        assert after["manual_severity"] == "high"
        assert after["resolve_comment"] == "zzz"
        assert after["status"] == "under_investigation"


class TestCortexHashListsAreStrings:
    """``hash_list`` is a flat list, and a malformed one is the caller's mistake."""

    def test_a_list_of_objects_is_a_400_not_a_500(
        self, client: TestClient, xdr_headers: dict,
    ) -> None:
        resp = client.post("/xdr/public_api/v1/hash_exceptions/blocklist/",
                           headers=xdr_headers,
                           json={"request_data": {"hash_list": [{"hash": "x"}]}})
        assert resp.status_code == 400
        assert resp.json()["reply"]["err_code"] == 400


class TestSplunkIndexKeepsWhatItWasGiven:
    """Measured against Splunk 10.4.2."""

    def test_create_keeps_the_settings(self, client: TestClient) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_index", "maxTotalDataSizeMB": "12345",
                          "frozenTimePeriodInSecs": "86400"})
        content = client.get("/splunk/services/data/indexes/zzz_index", headers=SPLUNK_AUTH,
                             params=JSON_OUT).json()["entry"][0]["content"]
        # splunkd answers both as numbers, whatever the form sent.
        assert content["maxTotalDataSizeMB"] == 12345
        assert content["frozenTimePeriodInSecs"] == 86400

    def test_the_paths_are_derived_from_the_name(self, client: TestClient) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_paths"})
        content = client.get("/splunk/services/data/indexes/zzz_paths", headers=SPLUNK_AUTH,
                             params=JSON_OUT).json()["entry"][0]["content"]
        assert content["homePath"] == "$SPLUNK_DB/zzz_paths/db"
        assert content["coldPath"] == "$SPLUNK_DB/zzz_paths/colddb"
        assert content["thawedPath"] == "$SPLUNK_DB/zzz_paths/thaweddb"

    def test_an_unknown_argument_is_refused_by_name(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                           data={"name": "zzz_reject", "zzzNotAThing": "1"})
        assert resp.status_code == 400
        assert (resp.json()["messages"][0]["text"]
                == 'Argument "zzzNotAThing" is not supported by this handler.')

    def test_output_mode_in_the_body_is_the_frameworks_not_the_handlers(
        self, client: TestClient,
    ) -> None:
        resp = client.post("/splunk/services/data/indexes", headers=FORM,
                           data={"output_mode": "json"})
        assert resp.status_code == 400
        assert "without a target name" in resp.text

    def test_an_index_is_edited_by_posting_to_its_own_url(self, client: TestClient) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_edit", "maxTotalDataSizeMB": "1"})
        resp = client.post("/splunk/services/data/indexes/zzz_edit", headers=FORM,
                           params=JSON_OUT, data={"maxTotalDataSizeMB": "777"})
        assert resp.status_code == 200
        assert resp.json()["entry"][0]["content"]["maxTotalDataSizeMB"] == 777

    def test_editing_an_index_that_is_not_there_is_a_404(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/data/indexes/zzz_absent", headers=FORM,
                           params=JSON_OUT, data={"maxTotalDataSizeMB": "1"})
        assert resp.status_code == 404

    def test_delete_answers_with_the_collection(self, client: TestClient) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_gone"})
        resp = client.delete("/splunk/services/data/indexes/zzz_gone", headers=SPLUNK_AUTH,
                             params=JSON_OUT)
        assert resp.status_code == 200
        names = [e["name"] for e in resp.json()["entry"]]
        assert "zzz_gone" not in names
        assert "main" in names

    def test_a_created_index_is_removable_and_a_system_one_is_not(
        self, client: TestClient,
    ) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_removable"})
        mine = client.get("/splunk/services/data/indexes/zzz_removable", headers=SPLUNK_AUTH,
                          params=JSON_OUT).json()["entry"][0]
        assert mine["acl"] == {**mine["acl"], "app": "search", "sharing": "app",
                               "removable": True}
        assert "remove" in mine["links"]

        system = client.get("/splunk/services/data/indexes/main", headers=SPLUNK_AUTH,
                            params=JSON_OUT).json()["entry"][0]
        assert system["acl"]["app"] == "system"
        assert system["acl"]["sharing"] == "system"
        assert system["acl"]["removable"] is False
        assert "remove" not in system["links"]

    def test_the_create_answer_has_no_fields_block(self, client: TestClient) -> None:
        """splunkd describes what was made, not what can now be done to it."""
        entry = client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                            data={"name": "zzz_created"}).json()["entry"][0]
        assert "fields" not in entry
        assert "disable" not in entry["links"]
        assert "remove" in entry["links"]

    def test_a_read_carries_the_writable_settings(self, client: TestClient) -> None:
        entry = client.get("/splunk/services/data/indexes/main", headers=SPLUNK_AUTH,
                           params=JSON_OUT).json()["entry"][0]
        assert entry["fields"]["required"] == []
        assert "maxTotalDataSizeMB" in entry["fields"]["optional"]


class TestSplunkFieldFilter:
    """``f`` is the REST framework's parameter, on every collection."""

    def test_f_narrows_the_content(self, client: TestClient) -> None:
        content = client.get("/splunk/services/data/indexes/main", headers=SPLUNK_AUTH,
                             params={**JSON_OUT, "f": "maxTotalDataSizeMB"},
                             ).json()["entry"][0]["content"]
        assert set(content) == {"maxTotalDataSizeMB", "eai:acl"}

    def test_f_is_repeatable(self, client: TestClient) -> None:
        response = client.get(
            "/splunk/services/data/indexes/main?output_mode=json"
            "&f=maxTotalDataSizeMB&f=datatype", headers=SPLUNK_AUTH,
        )
        assert set(response.json()["entry"][0]["content"]) == {
            "maxTotalDataSizeMB", "datatype", "eai:acl",
        }

    def test_f_takes_wildcards(self, client: TestClient) -> None:
        content = client.get("/splunk/services/data/indexes/main", headers=SPLUNK_AUTH,
                             params={**JSON_OUT, "f": "max*"},
                             ).json()["entry"][0]["content"]
        assert len(content) > 5
        assert all(k.startswith("max") or k == "eai:acl" for k in content)

    def test_a_field_that_matches_nothing_leaves_the_acl_alone(
        self, client: TestClient,
    ) -> None:
        content = client.get("/splunk/services/data/indexes/main", headers=SPLUNK_AUTH,
                             params={**JSON_OUT, "f": "zzzNoSuchField"},
                             ).json()["entry"][0]["content"]
        assert content == {"eai:acl": None}

    def test_f_applies_to_a_collection_too(self, client: TestClient) -> None:
        entries = client.get("/splunk/services/saved/searches", headers=SPLUNK_AUTH,
                             params={**JSON_OUT, "count": "2", "f": "search"},
                             ).json()["entry"]
        assert entries
        assert all(set(e["content"]) == {"search", "eai:acl"} for e in entries)


class TestWhoMayWrite:
    """A read-only credential must not perform a write.

    From ``scripts/authz_audit.py``, which asks every write route whether a
    credential without the right to it gets a 2xx. The two Splunk cases are
    measured: on 10.4.2 a ``power`` account posting to ``receivers/simple``
    is answered 200 and a ``user`` account 403, with a ``WARN`` message that
    names no capability — not the management refusal, which names one.
    """

    VIEWER = {"Authorization": "Basic " + base64.b64encode(
        b"viewer:mockdr-viewer").decode()}

    def test_a_reader_may_not_put_events_in_an_index(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/receivers/simple",
                           params={"index": "main", "sourcetype": "zzz",
                                   "output_mode": "json"},
                           headers=self.VIEWER, content=b"a line")
        assert resp.status_code == 403
        assert resp.json()["messages"] == [
            {"type": "WARN", "text": "insufficient permission to access this resource"},
        ]

    def test_an_admin_still_may(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/receivers/simple",
                           params={"index": "main", "sourcetype": "zzz"},
                           headers=SPLUNK_AUTH, content=b"a line")
        assert resp.status_code == 200

    def test_a_reader_may_not_change_a_notable(self, client: TestClient) -> None:
        """Enterprise Security gates this on ``edit_notable_events``."""
        resp = client.post("/splunk/services/notable_update", headers=self.VIEWER,
                           json={"ruleUIDs": ["x"], "status": "1"})
        assert resp.status_code == 403


class TestWhereAnEntryLives:
    """An entry's id says which app owns it, and under which user.

    Measured across the collections Splunk 10.4.2 serves: an entry whose ACL
    names an app is served with a namespaced id,
    ``/servicesNS/{owner}/{app}/{collection}/{name}``, and its links carry
    the same prefix. What the instance owns — users, roles, the server's own
    description — stays in the plain ``/services`` form. mockdr rendered
    every id plainly, so a client that parses owner and app out of an id
    found neither.
    """

    def _entry(self, client: TestClient, collection: str) -> dict:
        body = client.get(f"/splunk/services/{collection}", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "1"}).json()
        return body["entry"][0]

    def test_an_index_lives_in_system(self, client: TestClient) -> None:
        entry = self._entry(client, "data/indexes")
        assert entry["id"].startswith(
            "https://localhost:8089/servicesNS/nobody/system/data/indexes/")
        assert entry["acl"]["owner"] == "nobody"
        assert entry["acl"]["app"] == "system"

    def test_a_saved_search_lives_in_the_search_app(self, client: TestClient) -> None:
        entry = self._entry(client, "saved/searches")
        assert entry["id"].startswith(
            "https://localhost:8089/servicesNS/nobody/search/saved/searches/")
        assert entry["links"]["alternate"].startswith("/servicesNS/nobody/search/")

    def test_a_name_with_spaces_is_encoded_into_the_id(self, client: TestClient) -> None:
        entry = self._entry(client, "saved/searches")
        assert " " not in entry["id"]
        assert "%20" in entry["id"] or " " not in entry["name"]

    def test_a_user_belongs_to_no_app(self, client: TestClient) -> None:
        entry = self._entry(client, "authentication/users")
        assert entry["id"].startswith(
            "https://localhost:8089/services/authentication/users/")
        assert entry["acl"]["app"] == ""
        assert entry["acl"]["owner"] == "system"
        assert entry["acl"]["sharing"] == "system"

    def test_a_macro_is_a_knowledge_object(self, client: TestClient) -> None:
        entry = self._entry(client, "admin/macros")
        assert entry["id"].startswith(
            "https://localhost:8089/servicesNS/nobody/search/admin/macros/")
        # The four members that say who may re-share it.
        assert entry["acl"]["can_change_perms"] is True
        assert entry["acl"]["can_share_app"] is True
        assert entry["acl"]["can_share_global"] is True
        assert entry["acl"]["can_share_user"] is False
        assert entry["acl"]["removable"] is False

    def test_an_index_is_not_a_knowledge_object(self, client: TestClient) -> None:
        entry = self._entry(client, "data/indexes")
        assert "can_share_app" not in entry["acl"]

    def test_a_hec_token_lives_in_the_httpinput_app(self, client: TestClient) -> None:
        entry = self._entry(client, "data/inputs/http")
        assert "/servicesNS/nobody/splunk_httpinput/data/inputs/http/" in entry["id"]
        assert entry["acl"]["removable"] is True

    def test_a_job_names_a_user_and_an_app_and_is_still_not_namespaced(
        self, client: TestClient,
    ) -> None:
        """The measured exception."""
        client.post("/splunk/services/search/jobs", headers=FORM, params=JSON_OUT,
                    data={"search": "search index=main | head 1"})
        entry = self._entry(client, "search/jobs")
        assert entry["acl"]["app"] == "search"
        assert entry["acl"]["owner"] == "admin"
        assert entry["id"].startswith("https://localhost:8089/services/search/jobs/")

    def test_the_job_endpoint_ignores_the_field_filter(self, client: TestClient) -> None:
        """`f` narrows every other collection and not this one."""
        client.post("/splunk/services/search/jobs", headers=FORM, params=JSON_OUT,
                    data={"search": "search index=main | head 1"})
        content = client.get("/splunk/services/search/jobs", headers=SPLUNK_AUTH,
                             params={**JSON_OUT, "count": "1", "f": "zzzNoSuchField"},
                             ).json()["entry"][0]["content"]
        assert len(content) > 1


class TestARefusalIsShapedLikeItsVendor:
    """From ``scripts/error_envelope_audit.py``, which sweeps all 2 083 refusals.

    A client parses errors with one parser per vendor. A refusal in some
    other shape looks like a working refusal in a browser and breaks every
    integration that inspects it.
    """

    ES_AUTH = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def test_a_summary_of_a_list_that_is_not_there_is_a_404(
        self, client: TestClient,
    ) -> None:
        """It let the not-found straight out as a plain-text 500.

        The hostile probe never saw it: it sends malformed values, and this
        needs a *well-formed* id that resolves to nothing — the commonest
        thing a client sends.
        """
        resp = client.get("/kibana/api/exception_lists/summary", headers=self.ES_AUTH,
                          params={"list_id": "zzz-no-such-list"})
        assert resp.status_code == 404
        assert resp.headers["content-type"].startswith("application/json")
        assert "zzz-no-such-list" in resp.json()["message"]
        assert resp.json()["status_code"] == 404

    def test_deleting_a_document_that_is_not_there_answers_the_document_envelope(
        self, client: TestClient,
    ) -> None:
        """Measured on Elasticsearch 8.15: seven members, not an error object."""
        client.put("/elastic/zzz-del-test/_doc/a", headers=self.ES_AUTH, json={"x": 1})
        resp = client.delete("/elastic/zzz-del-test/_doc/no-such-doc", headers=self.ES_AUTH)
        assert resp.status_code == 404
        body = resp.json()
        assert body["result"] == "not_found"
        assert body["_index"] == "zzz-del-test"
        assert body["_id"] == "no-such-doc"
        # The four a client doing optimistic concurrency reads, which were absent.
        assert body["_version"] == 1
        assert body["_shards"] == {"total": 2, "successful": 1, "failed": 0}
        assert body["_seq_no"] == 0
        assert body["_primary_term"] == 1

    def test_a_successful_delete_carries_the_same_members(
        self, client: TestClient,
    ) -> None:
        client.put("/elastic/zzz-del-test2/_doc/a", headers=self.ES_AUTH, json={"x": 1})
        resp = client.delete("/elastic/zzz-del-test2/_doc/a", headers=self.ES_AUTH)
        assert resp.status_code == 200
        assert set(resp.json()) == {
            "_index", "_id", "_version", "result", "_shards", "_seq_no", "_primary_term",
        }


class TestTheSameRecordTwoWays:
    """From ``scripts/consistency_audit.py``: a listing and a fetch by id
    must describe the same record.

    Each route tends to be built separately, and the two drift: one
    serialises a field the other computes, one applies a projection the
    other does not. The result is a listing that says one thing and a fetch
    that says another, with a 200 either way.
    """

    def _both(self, client: TestClient, collection: str, name: str) -> tuple[dict, dict]:
        listed = client.get(f"/splunk/services/{collection}", headers=SPLUNK_AUTH,
                            params={**JSON_OUT, "count": "0"}).json()["entry"]
        listed = next(e for e in listed if e["name"] == name)
        fetched = client.get(f"/splunk/services/{collection}/{name}", headers=SPLUNK_AUTH,
                             params=JSON_OUT).json()["entry"][0]
        return listed["content"], fetched["content"]

    def test_an_index_names_its_own_buckets_in_both(self, client: TestClient) -> None:
        """The listing filled the three paths from the recorded `audit` entry."""
        listed, fetched = self._both(client, "data/indexes", "main")
        for key, expected in (
            ("homePath", "$SPLUNK_DB/main/db"),
            ("coldPath", "$SPLUNK_DB/main/colddb"),
            ("thawedPath", "$SPLUNK_DB/main/thaweddb"),
        ):
            assert listed[key] == expected
            assert fetched[key] == expected

    def test_a_saved_search_reports_its_alert_in_both(self, client: TestClient) -> None:
        """The single fetch left out the two members that define the alert."""
        listed, fetched = self._both(
            client, "saved/searches", "SentinelOne Threats - Last 24h")
        assert listed["alert_comparator"] == fetched["alert_comparator"]
        assert listed["alert_threshold"] == fetched["alert_threshold"]
        assert fetched["alert_comparator"] != ""

    def test_an_index_reports_the_time_range_it_holds(self, client: TestClient) -> None:
        """Measured on 10.4.2: a populated index carries bounds, an empty one ''.

        The offset has no colon here, which is not the format the rest of the
        API uses.
        """
        entries = {
            e["name"]: e["content"]
            for e in client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                                params={**JSON_OUT, "count": "0"}).json()["entry"]
        }
        populated = next(c for c in entries.values() if c["totalEventCount"])
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{4}",
                            populated["minTime"]), populated["minTime"]
        assert populated["minTime"] <= populated["maxTime"]

        empty = next((c for c in entries.values() if not c["totalEventCount"]), None)
        if empty is not None:
            assert empty["minTime"] == ""
            assert empty["maxTime"] == ""


class TestAFieldMeansOneThing:
    """From ``scripts/type_stability_audit.py``, which sweeps 1 189 records.

    A client writes one parser per field and runs it over every record. A
    field that is a string in one record and a number in the next breaks it,
    and which of the two is right barely matters — a product does not answer
    both.
    """

    def _mde(self, client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_a_process_id_is_a_number_or_absent_never_an_empty_string(
        self, client: TestClient,
    ) -> None:
        """Recorded from a real Defender reply: 39 integers, 56 nulls, no strings.

        The docs table types the fields it lists and says nothing about the
        ones that only appear in an example, so every member of `evidence`
        was defaulted to a string — including this one.
        """
        headers = self._mde(client)
        alerts = client.get("/mde/api/alerts", headers=headers,
                            params={"$top": 200}).json()["value"]
        seen = [
            evidence[field]
            for alert in alerts for evidence in alert.get("evidence") or []
            for field in ("processId", "parentProcessId") if field in evidence
        ]
        assert seen, "no evidence carried a process id"
        for value in seen:
            assert value is None or isinstance(value, int), repr(value)

    def test_an_empty_evidence_member_is_null_not_an_empty_string(
        self, client: TestClient,
    ) -> None:
        """Every member the recording ever saw empty, Defender sends as null."""
        headers = self._mde(client)
        alerts = client.get("/mde/api/alerts", headers=headers,
                            params={"$top": 200}).json()["value"]
        empties = [
            (field, value)
            for alert in alerts for evidence in alert.get("evidence") or []
            for field, value in evidence.items()
            if field not in ("entityType", "evidenceCreationTime") and value == ""
        ]
        assert empties == [], f"empty strings where the product sends null: {empties[:5]}"


class TestGraphAlertEvidenceIsGraphsOwnShape:
    """``microsoft.graph.security.deviceEvidence``, from the vendored CSDL.

    Found by asking whether a reference resolves: the alert evidence named a
    device with `{"type": "device", "deviceId": …}`, which is not a shape
    Graph has — so a client reading `mdeDeviceId`, the property that exists
    for exactly this, found nothing, and the id it did carry matched no
    device the mock serves.
    """

    def _graph(self, client: TestClient) -> dict:
        token = client.post("/graph/oauth2/v2.0/token", data={
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _mde(self, client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_evidence_is_typed_and_carries_the_declared_members(
        self, client: TestClient,
    ) -> None:
        alerts = client.get("/graph/v1.0/security/alerts_v2", headers=self._graph(client),
                            params={"$top": 5}).json()["value"]
        evidence = [e for a in alerts for e in a.get("evidence") or []]
        assert evidence
        for item in evidence:
            assert item["@odata.type"] == "#microsoft.graph.security.deviceEvidence"
            # The base type's members, on every evidence item whatever its kind.
            for member in ("createdDateTime", "verdict", "remediationStatus",
                           "roles", "tags", "detailedRoles"):
                assert member in item, member
            # And the two the invented shape replaced.
            assert item["mdeDeviceId"]
            assert "deviceId" not in item
            assert "type" not in item

    def test_the_enums_are_graphs_spelling_not_defenders(
        self, client: TestClient,
    ) -> None:
        """Defender writes `Active`, Graph writes `active`."""
        health = {"active", "inactive", "impairedCommunication", "noSensorData",
                  "noSensorDataImpairedCommunication", "unknown", "unknownFutureValue"}
        onboarding = {"insufficientInfo", "onboarded", "canBeOnboarded", "unsupported",
                      "unknownFutureValue"}
        risk = {"none", "informational", "low", "medium", "high", "unknownFutureValue"}
        alerts = client.get("/graph/v1.0/security/alerts_v2", headers=self._graph(client),
                            params={"$top": 200}).json()["value"]
        for item in (e for a in alerts for e in a.get("evidence") or []):
            assert item["healthStatus"] in health, item["healthStatus"]
            assert item["onboardingStatus"] in onboarding, item["onboardingStatus"]
            assert item["riskScore"] in risk, item["riskScore"]

    def test_the_device_it_names_is_one_defender_serves(
        self, client: TestClient,
    ) -> None:
        """A client that follows the reference must find a machine there."""
        alerts = client.get("/graph/v1.0/security/alerts_v2", headers=self._graph(client),
                            params={"$top": 200}).json()["value"]
        referenced = {e["mdeDeviceId"] for a in alerts for e in a.get("evidence") or []}
        machines = {
            m["id"] for m in
            client.get("/mde/api/machines", headers=self._mde(client),
                       params={"$top": 200}).json()["value"]
        }
        assert referenced
        assert referenced <= machines, sorted(referenced - machines)[:3]

    def test_the_host_it_describes_is_the_machine_defender_describes(
        self, client: TestClient,
    ) -> None:
        """Two products' views of one host must agree."""
        alerts = client.get("/graph/v1.0/security/alerts_v2", headers=self._graph(client),
                            params={"$top": 200}).json()["value"]
        machines = {
            m["id"]: m for m in
            client.get("/mde/api/machines", headers=self._mde(client),
                       params={"$top": 200}).json()["value"]
        }
        for item in (e for a in alerts for e in a.get("evidence") or []):
            machine = machines[item["mdeDeviceId"]]
            assert item["deviceDnsName"] == machine["computerDnsName"]
            assert item["osPlatform"] == machine["osPlatform"]
            assert item["lastIpAddress"] == machine["lastIpAddress"]


class TestAnEnumSortsByItsDeclaredOrder:
    """OData orders an enum by where the member sits, not by its spelling.

    A triage client asks for the worst alerts first. Sorted as text, the mock
    answered `medium` at the top of a descending severity sort where both
    products answer `high` — and there is nothing in the reply to tell the
    client it worked on the wrong ones.

    The orders come from what is vendored: Graph's from the CSDL, Defender's
    from its docs' properties tables.
    """

    def _graph(self, client: TestClient) -> dict:
        token = client.post("/graph/oauth2/v2.0/token", data={
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _mde(self, client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _runs(values: list[str]) -> list[str]:
        out: list[str] = []
        for value in values:
            if not out or out[-1] != value:
                out.append(value)
        return out

    def test_graph_alerts_descend_from_high(self, client: TestClient) -> None:
        values = [
            a["severity"] for a in
            client.get("/graph/v1.0/security/alerts_v2", headers=self._graph(client),
                       params={"$top": 200, "$orderby": "severity desc"}).json()["value"]
        ]
        assert self._runs(values) == ["high", "medium", "low", "informational"]

    def test_graph_alerts_ascend_to_high(self, client: TestClient) -> None:
        values = [
            a["severity"] for a in
            client.get("/graph/v1.0/security/alerts_v2", headers=self._graph(client),
                       params={"$top": 200, "$orderby": "severity asc"}).json()["value"]
        ]
        assert self._runs(values) == ["informational", "low", "medium", "high"]

    def test_defender_alerts_descend_from_high(self, client: TestClient) -> None:
        values = [
            a["severity"] for a in
            client.get("/mde/api/alerts", headers=self._mde(client),
                       params={"$top": 200, "$orderby": "severity desc"}).json()["value"]
        ]
        assert self._runs(values) == ["High", "Medium", "Low", "Informational"]

    def test_a_field_that_is_not_an_enum_still_sorts_as_before(
        self, client: TestClient,
    ) -> None:
        values = [
            m["computerDnsName"] for m in
            client.get("/mde/api/machines", headers=self._mde(client),
                       params={"$top": 50, "$orderby": "computerDnsName asc"}).json()["value"]
        ]
        assert values == sorted(values)


class TestACollectionComesBackInOrder:
    """Measured on Splunk 10.4.2, where every collection is sorted by name.

    mockdr answered in whatever order its store held and ignored both
    parameters while declaring them, so `sort_dir=desc` came back identical
    to `sort_dir=asc` — and a client paging through a collection had no
    guarantee of seeing each record once.
    """

    def _names(self, client: TestClient, **params: str) -> list[str]:
        body = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "0", **params}).json()
        return [e["name"] for e in body["entry"]]

    def test_the_default_order_is_by_name_ascending(self, client: TestClient) -> None:
        names = self._names(client)
        assert names == sorted(names)

    def test_sort_dir_descending_reverses_it(self, client: TestClient) -> None:
        names = self._names(client, sort_dir="desc")
        assert names == sorted(names, reverse=True)

    def test_a_content_field_sorts_numerically(self, client: TestClient) -> None:
        body = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "0",
                                  "sort_key": "totalEventCount", "sort_dir": "desc"}).json()
        counts = [e["content"]["totalEventCount"] for e in body["entry"]]
        assert counts == sorted(counts, reverse=True)

    def test_a_key_nothing_carries_leaves_the_order_alone(
        self, client: TestClient,
    ) -> None:
        """splunkd answers 200 and does not reorder by nothing."""
        assert self._names(client, sort_key="zzzNoSuchKey") != []

    def test_the_collection_is_sorted_before_it_is_paged(
        self, client: TestClient,
    ) -> None:
        """Sorting a page would order each page separately."""
        whole = self._names(client)
        first = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                           params={**JSON_OUT, "count": "3"}).json()["entry"]
        assert [e["name"] for e in first] == whole[:3]


class TestAnIndexIsDisabledThroughItsOwnLink:
    """The link the entry publishes has to lead somewhere.

    An index is not disabled by editing a `disabled` argument — the handler
    refuses that name — but through `POST …/{name}/disable`. mockdr published
    both links and answered 404 at the end of them.
    """

    def _entry(self, client: TestClient, name: str) -> dict:
        return client.get(f"/splunk/services/data/indexes/{name}", headers=SPLUNK_AUTH,
                          params=JSON_OUT).json()["entry"][0]

    def test_disable_then_enable(self, client: TestClient) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_state"})
        assert self._entry(client, "zzz_state")["content"]["disabled"] is False

        answer = client.post("/splunk/services/data/indexes/zzz_state/disable",
                             headers=SPLUNK_AUTH, params=JSON_OUT)
        assert answer.status_code == 200
        assert answer.json()["entry"][0]["content"]["disabled"] is True
        # The answer describes what was done, not what can be done next.
        assert "disable" not in answer.json()["entry"][0]["links"]
        assert "enable" not in answer.json()["entry"][0]["links"]

        # And a later read offers the action that is now available.
        read = self._entry(client, "zzz_state")
        assert read["content"]["disabled"] is True
        assert "enable" in read["links"]
        assert "disable" not in read["links"]

        client.post("/splunk/services/data/indexes/zzz_state/enable",
                    headers=SPLUNK_AUTH, params=JSON_OUT)
        read = self._entry(client, "zzz_state")
        assert read["content"]["disabled"] is False
        assert "disable" in read["links"]
        assert "enable" not in read["links"]

    def test_an_index_that_is_not_there(self, client: TestClient) -> None:
        answer = client.post("/splunk/services/data/indexes/zzz_absent/disable",
                             headers=SPLUNK_AUTH, params=JSON_OUT)
        assert answer.status_code == 404

    def test_disabled_is_not_an_argument_the_handler_takes(
        self, client: TestClient,
    ) -> None:
        client.post("/splunk/services/data/indexes", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_arg"})
        answer = client.post("/splunk/services/data/indexes/zzz_arg", headers=FORM,
                             params=JSON_OUT, data={"disabled": "1"})
        assert answer.status_code == 400


class TestACollectionCanBeNarrowed:
    """``search`` on a collection, measured on Splunk 10.4.2.

    mockdr declared the parameter and ignored it, so a client narrowing a
    collection was handed all of it — with a ``paging.total`` that agreed
    with the answer rather than with the question.
    """

    def _indexes(self, client: TestClient, **params: str) -> dict:
        return client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "0", **params}).json()

    def test_a_field_match_selects_one(self, client: TestClient) -> None:
        body = self._indexes(client, search="name=main")
        assert [e["name"] for e in body["entry"]] == ["main"]
        assert body["paging"]["total"] == 1

    def test_a_term_nothing_matches_answers_an_empty_collection(
        self, client: TestClient,
    ) -> None:
        body = self._indexes(client, search="zzz-no-such-index")
        assert body["entry"] == []
        assert body["paging"]["total"] == 0

    def test_a_bare_term_matches_content_and_not_only_the_name(
        self, client: TestClient,
    ) -> None:
        """`search=main` matches every index: each carries `defaultDatabase: main`."""
        assert len(self._indexes(client, search="main")["entry"]) > 1

    def test_the_search_happens_before_the_page_is_cut(
        self, client: TestClient,
    ) -> None:
        body = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "1", "search": "name=main"}).json()
        assert [e["name"] for e in body["entry"]] == ["main"]
        assert body["paging"]["total"] == 1

    def test_the_search_route_is_left_alone(self, client: TestClient) -> None:
        """There, `search` is the search string, not a filter over a collection."""
        answer = client.post("/splunk/services/search/jobs", headers=FORM,
                             params=JSON_OUT,
                             data={"search": "search index=main | head 1",
                                   "exec_mode": "oneshot", "output_mode": "json"})
        assert answer.status_code in (200, 201)


class TestTheEnvelopeSaysWhereItCameFrom:
    """``origin`` names the collection, and ``perPage`` its page size."""

    def test_origin_names_the_collection(self, client: TestClient) -> None:
        for collection in ("data/indexes", "saved/searches", "authentication/users"):
            body = client.get(f"/splunk/services/{collection}", headers=SPLUNK_AUTH,
                              params={**JSON_OUT, "count": "1"}).json()
            assert body["origin"].endswith(f"/services/{collection}"), collection

    def test_count_zero_reports_splunkds_own_maximum(self, client: TestClient) -> None:
        """`count=0` means "all", and splunkd reports 10000000 — not the count."""
        body = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "0"}).json()
        assert body["paging"]["perPage"] == 10000000
        assert body["paging"]["total"] == len(body["entry"])

    def test_a_real_page_size_is_reported_as_itself(self, client: TestClient) -> None:
        body = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "3"}).json()
        assert body["paging"]["perPage"] == 3


class TestHowACollectionCompares:
    """``sort_mode``, measured on Splunk 10.4.2.

    A descending *alpha* sort of the event counts 97716, 31270, 5907, 4483
    is `97716, 5907, 4483, 31270` — the values compared as text. mockdr
    ignored the parameter and always compared numerically, so a client
    asking for one order got the other.
    """

    def _counts(self, client: TestClient, **params: str) -> list[int]:
        body = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                          params={**JSON_OUT, "count": "0",
                                  "sort_key": "totalEventCount", **params}).json()
        return [e["content"]["totalEventCount"] for e in body["entry"]]

    def test_auto_compares_numbers_as_numbers(self, client: TestClient) -> None:
        counts = self._counts(client, sort_dir="desc")
        assert counts == sorted(counts, reverse=True)

    def test_num_does_the_same(self, client: TestClient) -> None:
        counts = self._counts(client, sort_dir="desc", sort_mode="num")
        assert counts == sorted(counts, reverse=True)

    def test_alpha_compares_them_as_text(self, client: TestClient) -> None:
        counts = self._counts(client, sort_dir="desc", sort_mode="alpha")
        assert counts == sorted(counts, key=str, reverse=True)
        # And that is a different order, which is the whole point.
        assert counts != sorted(counts, reverse=True)

    def test_alpha_ignores_case_and_alpha_case_does_not(
        self, client: TestClient,
    ) -> None:
        """Splunk's documented meaning; this install has no pair to measure."""
        names = [
            e["name"] for e in
            client.get("/splunk/services/saved/searches", headers=SPLUNK_AUTH,
                       params={**JSON_OUT, "count": "0", "sort_key": "name",
                               "sort_mode": "alpha"}).json()["entry"]
        ]
        assert names == sorted(names, key=str.lower)
        cased = [
            e["name"] for e in
            client.get("/splunk/services/saved/searches", headers=SPLUNK_AUTH,
                       params={**JSON_OUT, "count": "0", "sort_key": "name",
                               "sort_mode": "alpha_case"}).json()["entry"]
        ]
        assert cased == sorted(cased)


class TestUriSearch:
    """``_search?q=…&size=…``, measured against Elasticsearch 8.15.

    It is the form a client reaches for from a shell, and mockdr read none
    of it: the whole index came back, unfiltered, unsorted and unlimited,
    with a 200.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    @pytest.fixture(autouse=True)
    def _documents(self, client: TestClient) -> None:
        for doc_id, name, number in ((1, "alpha", 1), (2, "beta", 2), (3, "gamma", 3)):
            client.put(f"/elastic/zzz-uri/_doc/{doc_id}", headers=self.ES,
                       params={"refresh": "true"}, json={"name": name, "n": number})

    def _hits(self, client: TestClient, **params: str) -> dict:
        return client.get("/elastic/zzz-uri/_search", headers=self.ES,
                          params=params).json()["hits"]

    def test_size_cuts_the_page(self, client: TestClient) -> None:
        hits = self._hits(client, size="1")
        assert len(hits["hits"]) == 1
        # And the total still counts the whole match.
        assert hits["total"]["value"] == 3

    def test_from_skips_into_it(self, client: TestClient) -> None:
        hits = self._hits(client, **{"from": "1", "size": "1", "sort": "n:asc"})
        assert [h["_source"]["n"] for h in hits["hits"]] == [2]

    def test_q_filters(self, client: TestClient) -> None:
        hits = self._hits(client, q="name:beta")
        assert [h["_source"]["name"] for h in hits["hits"]] == ["beta"]
        assert hits["total"]["value"] == 1

    def test_sort_orders(self, client: TestClient) -> None:
        hits = self._hits(client, sort="n:desc")
        assert [h["_source"]["n"] for h in hits["hits"]] == [3, 2, 1]

    def test_source_includes_projects(self, client: TestClient) -> None:
        hits = self._hits(client, _source_includes="name", sort="n:asc")
        assert hits["hits"][0]["_source"] == {"name": "alpha"}

    def test_source_false_drops_it(self, client: TestClient) -> None:
        hits = self._hits(client, _source="false")
        assert "_source" not in hits["hits"][0]

    def test_size_zero_answers_the_count_and_no_hits(self, client: TestClient) -> None:
        hits = self._hits(client, size="0")
        assert hits["hits"] == []
        assert hits["total"]["value"] == 3

    def test_track_total_hits_false_leaves_the_total_out(
        self, client: TestClient,
    ) -> None:
        """Not zero — absent."""
        assert "total" not in self._hits(client, track_total_hits="false")

    def test_the_query_string_wins_over_the_body(self, client: TestClient) -> None:
        body = client.post("/elastic/zzz-uri/_search", headers=self.ES,
                           params={"size": "1"},
                           json={"size": 3, "query": {"match_all": {}}}).json()
        assert len(body["hits"]["hits"]) == 1

    def test_a_size_that_is_not_a_number_is_refused(self, client: TestClient) -> None:
        answer = client.get("/elastic/zzz-uri/_search", headers=self.ES,
                            params={"size": "zzz"})
        assert answer.status_code == 400


class TestUriQueryOnTheOtherRoutes:
    """`q` narrows a count and a delete, not only a search.

    The delete is the one that mattered: `_delete_by_query?q=name:zzz`
    emptied the index here and deleted nothing on a cluster, so a targeted
    deletion became a wipe — reported as a 200 whose numbers nobody reads.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    @pytest.fixture(autouse=True)
    def _documents(self, client: TestClient) -> None:
        for doc_id, name in ((1, "alpha"), (2, "beta"), (3, "gamma")):
            client.put(f"/elastic/zzz-del-q/_doc/{doc_id}", headers=self.ES,
                       params={"refresh": "true"}, json={"name": name})

    def _count(self, client: TestClient, **params: str) -> int:
        return client.get("/elastic/zzz-del-q/_count", headers=self.ES,
                          params=params).json()["count"]

    def test_count_honours_q(self, client: TestClient) -> None:
        assert self._count(client) == 3
        assert self._count(client, q="name:beta") == 1
        assert self._count(client, q="name:zzz") == 0

    def test_a_delete_that_matches_nothing_deletes_nothing(
        self, client: TestClient,
    ) -> None:
        answer = client.post("/elastic/zzz-del-q/_delete_by_query", headers=self.ES,
                             params={"q": "name:zzz", "refresh": "true"}).json()
        assert answer["deleted"] == 0
        assert answer["total"] == 0
        assert self._count(client) == 3

    def test_a_delete_that_matches_one_deletes_one(self, client: TestClient) -> None:
        answer = client.post("/elastic/zzz-del-q/_delete_by_query", headers=self.ES,
                             params={"q": "name:beta", "refresh": "true"}).json()
        assert answer["deleted"] == 1
        assert self._count(client) == 2

    def test_update_by_query_is_narrowed_the_same_way(
        self, client: TestClient,
    ) -> None:
        answer = client.post("/elastic/zzz-del-q/_update_by_query", headers=self.ES,
                             params={"q": "name:zzz", "refresh": "true"},
                             json={"script": {"source": "ctx._source.n = 1"}}).json()
        assert answer["updated"] == 0


class TestTheCatApiReadsItsParameters:
    """`_cat` is a text API driven entirely by its query string.

    Measured against Elasticsearch 8.15.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def test_a_bare_v_asks_for_the_header_row(self, client: TestClient) -> None:
        """`?v` — no value — is the commonest `_cat` request there is.

        Declared as a boolean, FastAPI refused the empty value with a 400.
        """
        answer = client.get("/elastic/_cat/indices?v", headers=self.ES)
        assert answer.status_code == 200
        first = answer.text.splitlines()[0]
        assert first.split()[:3] == ["health", "status", "index"]

    def test_v_false_still_means_false(self, client: TestClient) -> None:
        answer = client.get("/elastic/_cat/indices", headers=self.ES,
                            params={"v": "false"})
        assert not answer.text.splitlines()[0].startswith("health status")

    def test_h_picks_the_columns_of_the_json_form_too(
        self, client: TestClient,
    ) -> None:
        rows = client.get("/elastic/_cat/indices", headers=self.ES,
                          params={"format": "json", "h": "index,docs.count"}).json()
        assert rows
        assert all(set(row) == {"index", "docs.count"} for row in rows)

    def test_a_column_no_row_carries_is_simply_left_out(
        self, client: TestClient,
    ) -> None:
        rows = client.get("/elastic/_cat/indices", headers=self.ES,
                          params={"format": "json", "h": "index,zzzNope"}).json()
        assert all(set(row) == {"index"} for row in rows)

    def test_s_orders_the_rows(self, client: TestClient) -> None:
        rows = client.get("/elastic/_cat/indices", headers=self.ES,
                          params={"format": "json", "s": "index:desc",
                                  "h": "index"}).json()
        names = [r["index"] for r in rows]
        assert names == sorted(names, reverse=True)

    def test_s_sorts_a_numeric_column_numerically(self, client: TestClient) -> None:
        rows = client.get("/elastic/_cat/indices", headers=self.ES,
                          params={"format": "json", "s": "docs.count:desc",
                                  "h": "index,docs.count"}).json()
        counts = [int(r["docs.count"]) for r in rows]
        assert counts == sorted(counts, reverse=True)

    def test_sorting_by_a_column_nothing_carries_is_a_400(
        self, client: TestClient,
    ) -> None:
        answer = client.get("/elastic/_cat/indices", headers=self.ES,
                            params={"format": "json", "s": "zzzNope"})
        assert answer.status_code == 400
        error = answer.json()["error"]
        assert error["type"] == "illegal_argument_exception"
        assert error["reason"] == "Unable to sort by unknown sort key `zzzNope`"


class TestTheHttpLevelItself:
    """Two things below the JSON, measured against Elasticsearch 8.15."""

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def test_head_is_served_where_existence_is_the_question(
        self, client: TestClient,
    ) -> None:
        assert client.head("/elastic/", headers=self.ES).status_code == 200
        assert client.head("/elastic/logs-endpoint", headers=self.ES).status_code == 200
        assert client.head("/elastic/zzz-no-such-index",
                           headers=self.ES).status_code == 404

    def test_head_is_405_where_it_is_not(self, client: TestClient) -> None:
        """A client asking "does this exist" got a 200 from a path that
        cannot answer it."""
        for path in ("/elastic/_cluster/health", "/elastic/_cat/indices",
                     "/elastic/logs-endpoint/_search"):
            assert client.head(path, headers=self.ES).status_code == 405, path

    def test_kibana_still_answers_head_wherever_it_answers_get(
        self, client: TestClient,
    ) -> None:
        """Kibana does serve it broadly, so the restriction is Elasticsearch's."""
        assert client.head("/kibana/api/status", headers=self.ES).status_code == 200

    def test_each_challenge_is_its_own_header(self, client: TestClient) -> None:
        """Folding them into one value is ambiguous: the first contains a comma.

        `Basic realm="security", charset="UTF-8", ApiKey` cannot be split
        back into the two schemes it came from.
        """
        answer = client.get("/elastic/_cluster/health")
        assert answer.status_code == 401
        challenges = [
            value for name, value in answer.headers.raw
            if name.decode().lower() == "www-authenticate"
        ]
        assert [c.decode() for c in challenges] == [
            'Basic realm="security", charset="UTF-8"', "ApiKey",
        ]


class TestKibanaAndElasticsearchDifferBelowTheJson:
    """They ship together and differ in three ways, all measured on 8.15."""

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}
    KBN = {**ES, "kbn-xsrf": "true"}

    def test_a_verb_kibana_does_not_take_is_a_404(self, client: TestClient) -> None:
        answer = client.request("DELETE", "/kibana/api/cases/_find", headers=self.KBN)
        assert answer.status_code == 404
        assert answer.json() == {
            "statusCode": 404, "error": "Not Found", "message": "Not Found",
        }
        assert "allow" not in {k.lower() for k in answer.headers}

    def test_a_verb_elasticsearch_does_not_take_is_a_405_with_allow(
        self, client: TestClient,
    ) -> None:
        answer = client.request("DELETE", "/elastic/_cluster/health", headers=self.ES)
        assert answer.status_code == 405
        assert "GET" in answer.headers["allow"]

    def test_kibana_says_only_not_found_for_an_unknown_path(
        self, client: TestClient,
    ) -> None:
        answer = client.get("/kibana/api/zzz-no-such-route", headers=self.KBN)
        assert answer.json()["message"] == "Not Found"

    def test_each_product_names_the_charset_its_own_way(
        self, client: TestClient,
    ) -> None:
        """Kibana lower-case, splunkd upper-case, Elasticsearch not at all."""
        kibana = client.get("/kibana/api/cases/_find", headers=self.KBN)
        assert kibana.headers["content-type"] == "application/json; charset=utf-8"

        splunk = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH,
                            params=JSON_OUT)
        assert splunk.headers["content-type"] == "application/json; charset=UTF-8"

        elastic = client.get("/elastic/_cluster/health", headers=self.ES)
        assert elastic.headers["content-type"] == "application/json"

    def test_splunks_xml_and_hec_carry_it_too(self, client: TestClient) -> None:
        xml = client.get("/splunk/services/data/indexes", headers=SPLUNK_AUTH)
        assert xml.headers["content-type"] == "text/xml; charset=UTF-8"

        hec = client.post(
            "/splunk/services/collector/event",
            headers={"Authorization": "Splunk 11111111-1111-1111-1111-111111111111"},
            json={"event": "x"},
        )
        assert hec.headers["content-type"] == "application/json; charset=UTF-8"

    def test_a_refusal_carries_it_as_well(self, client: TestClient) -> None:
        """Where a client is most likely reading headers rather than a body."""
        answer = client.get("/splunk/services/data/indexes", params=JSON_OUT)
        assert answer.status_code == 401
        assert answer.headers["content-type"] == "application/json; charset=UTF-8"

    def test_the_charset_is_added_to_kibanas_errors_too(
        self, client: TestClient,
    ) -> None:
        answer = client.get("/kibana/api/cases/no-such-case", headers=self.KBN)
        assert answer.status_code == 404
        assert answer.headers["content-type"] == "application/json; charset=utf-8"


class TestAParameterDoesNotSwallowItsSibling:
    """From ``scripts/http_contract_audit.py``.

    ``…/jobs/{sid}`` and ``…/jobs/export`` are two endpoints, and a parameter
    that matches anything matches the second as well. The same pair exists in
    the KV store, and in Elasticsearch, where ``/{index}`` matched every one
    of its underscore-prefixed endpoints — the mock's own error message
    ("must not start with '_'") is the rule the product states.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def test_export_is_not_a_search_job(self, client: TestClient) -> None:
        answer = client.request("DELETE", "/splunk/services/search/jobs/export",
                                headers=SPLUNK_AUTH, params=JSON_OUT)
        assert answer.status_code == 405
        assert answer.json()["messages"][0]["text"] == "The method is not allowed."
        assert answer.headers["allow"] == "POST"

    def test_batch_find_is_not_a_record_key(self, client: TestClient) -> None:
        answer = client.request(
            "DELETE",
            "/splunk/servicesNS/nobody/search/storage/collections/data/zzz/batch_find",
            headers=SPLUNK_AUTH, params=JSON_OUT)
        assert answer.status_code == 405
        assert answer.json()["messages"][0]["text"] == "Method Not Allowed"

    def test_a_real_sid_still_reaches_the_job_route(self, client: TestClient) -> None:
        answer = client.get("/splunk/services/search/jobs/no-such-sid",
                            headers=SPLUNK_AUTH, params=JSON_OUT)
        assert answer.status_code == 404
        assert answer.json()["messages"][0]["text"] == "Unknown sid."

    def test_an_underscore_path_is_not_an_index(self, client: TestClient) -> None:
        answer = client.request("DELETE", "/elastic/_search", headers=self.ES)
        assert answer.status_code == 405
        assert answer.headers["allow"] == "GET,POST"
        assert "Incorrect HTTP method" in answer.json()["error"]

    def test_all_is_the_exception(self, client: TestClient) -> None:
        """`_all` names every index rather than one, and still routes."""
        assert client.get("/elastic/_all/_count", headers=self.ES).status_code == 200

    def test_a_real_index_still_reaches_the_index_route(
        self, client: TestClient,
    ) -> None:
        answer = client.request("DELETE", "/elastic/zzz-not-there", headers=self.ES)
        assert answer.status_code == 404
        assert answer.json()["error"]["type"] == "index_not_found_exception"

    def test_allow_lists_only_what_is_served(self, client: TestClient) -> None:
        """No space after the comma, and no HEAD where HEAD is not served."""
        answer = client.request("PATCH", "/elastic/_cluster/health", headers=self.ES)
        assert answer.headers["allow"] == "GET"
        index = client.request("PATCH", "/elastic/logs-endpoint", headers=self.ES)
        assert index.headers["allow"] == "GET,PUT,DELETE,HEAD"

    def test_export_and_parser_take_no_get(self, client: TestClient) -> None:
        for path in ("/splunk/services/search/jobs/export",
                     "/splunk/services/search/parser"):
            answer = client.get(path, headers=SPLUNK_AUTH, params=JSON_OUT)
            assert answer.status_code == 405, path
            assert answer.headers["allow"] == "POST", path


class TestTwoClientsWritingTheSameDocument:
    """Optimistic concurrency, measured against Elasticsearch 8.15.

    Two clients read the same document and both write it. Without the
    precondition both succeed and one write is lost — silently, with a 200
    each. That is what `_seq_no` is handed out for, and mockdr handed it out
    and never checked it.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def _write(self, client: TestClient, doc_id: str, body: dict, **params: str) -> dict:
        answer = client.put(f"/elastic/zzz-cc/_doc/{doc_id}", headers=self.ES,
                            params={"refresh": "true", **params}, json=body)
        return {"status": answer.status_code, **answer.json()}

    def test_a_write_at_the_current_seq_no_succeeds(self, client: TestClient) -> None:
        first = self._write(client, "a", {"v": 1})
        again = self._write(client, "a", {"v": 2},
                            if_seq_no=str(first["_seq_no"]),
                            if_primary_term=str(first["_primary_term"]))
        assert again["status"] == 200
        assert again["result"] == "updated"

    def test_the_second_of_two_writers_is_refused(self, client: TestClient) -> None:
        first = self._write(client, "b", {"v": 1})
        # Both clients read the same seq_no; the first one to write moves it.
        self._write(client, "b", {"v": 2}, if_seq_no=str(first["_seq_no"]),
                    if_primary_term="1")
        loser = self._write(client, "b", {"v": 3}, if_seq_no=str(first["_seq_no"]),
                            if_primary_term="1")
        assert loser["status"] == 409
        assert loser["error"]["type"] == "version_conflict_engine_exception"
        assert "version conflict, required seqNo" in loser["error"]["reason"]

    def test_half_the_pair_is_a_validation_failure(self, client: TestClient) -> None:
        self._write(client, "c", {"v": 1})
        answer = client.put("/elastic/zzz-cc/_doc/c", headers=self.ES,
                            params={"if_seq_no": "0"}, json={"v": 2})
        assert answer.status_code == 400
        assert answer.json()["error"]["type"] == "action_request_validation_exception"

    def test_a_delete_carries_the_same_precondition(self, client: TestClient) -> None:
        self._write(client, "d", {"v": 1})
        answer = client.delete("/elastic/zzz-cc/_doc/d", headers=self.ES,
                               params={"if_seq_no": "99", "if_primary_term": "1"})
        assert answer.status_code == 409

    def test_an_update_carries_it_too(self, client: TestClient) -> None:
        self._write(client, "e", {"v": 1})
        answer = client.post("/elastic/zzz-cc/_update/e", headers=self.ES,
                             params={"if_seq_no": "99", "if_primary_term": "1"},
                             json={"doc": {"v": 2}})
        assert answer.status_code == 409

    def test_the_sequence_counts_writes_to_the_index_not_versions(
        self, client: TestClient,
    ) -> None:
        """Three documents created get 0, 1, 2 — and rewriting the first gets 3.

        Derived from each document's own version instead, every freshly
        created document claimed `_seq_no: 0`, and a client reasoning about
        write order across documents read a number that meant nothing.
        """
        seq = [self._write(client, f"s{i}", {"v": 1})["_seq_no"] for i in range(3)]
        assert seq == sorted(seq)
        assert len(set(seq)) == 3
        again = self._write(client, "s0", {"v": 2})["_seq_no"]
        assert again > max(seq)

    def test_a_noop_update_does_not_move_the_sequence(
        self, client: TestClient,
    ) -> None:
        written = self._write(client, "n", {"v": 1})
        answer = client.post("/elastic/zzz-cc/_update/n", headers=self.ES,
                             json={"doc": {"v": 1}}).json()
        assert answer["result"] == "noop"
        assert answer["_seq_no"] == written["_seq_no"]


class TestTwoPeopleEditingOneComment:
    """A case comment carries a version token, and it has to mean something.

    Measured on Kibana 8.15: a PATCH whose ``version`` is no longer the
    current one is a 409, and the message names the *case*.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    def _case_with_comment(self, client: TestClient) -> tuple[str, dict]:
        case = client.post("/kibana/api/cases", headers=self.KBN, json={
            "title": "zzz-versions", "description": "d", "tags": [],
            "connector": {"id": "none", "name": "none", "type": ".none", "fields": None},
            "settings": {"syncAlerts": False}, "owner": "securitySolution",
        }).json()
        body = client.post(f"/kibana/api/cases/{case['id']}/comments", headers=self.KBN,
                           json={"type": "user", "comment": "one",
                                 "owner": "securitySolution"}).json()
        return case["id"], body["comments"][-1]

    def _patch(self, client: TestClient, case_id: str, comment: dict,
               version: str, text: str) -> object:
        return client.patch(f"/kibana/api/cases/{case_id}/comments", headers=self.KBN,
                            json={"id": comment["id"], "version": version,
                                  "type": "user", "comment": text,
                                  "owner": "securitySolution"})

    def test_the_current_version_is_accepted(self, client: TestClient) -> None:
        case_id, comment = self._case_with_comment(client)
        answer = self._patch(client, case_id, comment, comment["version"], "two")
        assert answer.status_code == 200

    def test_the_version_moves_on_every_write(self, client: TestClient) -> None:
        case_id, comment = self._case_with_comment(client)
        answer = self._patch(client, case_id, comment, comment["version"], "two")
        after = next(c for c in answer.json()["comments"] if c["id"] == comment["id"])
        assert after["version"] != comment["version"]

    def test_the_second_of_two_editors_is_refused(self, client: TestClient) -> None:
        case_id, comment = self._case_with_comment(client)
        self._patch(client, case_id, comment, comment["version"], "two")
        loser = self._patch(client, case_id, comment, comment["version"], "three")
        assert loser.status_code == 409
        assert loser.json() == {
            "statusCode": 409, "error": "Conflict",
            "message": "This case has been updated. Please refresh before "
                       "saving additional updates.",
        }

    def test_a_missing_saved_object_is_named_as_one(self, client: TestClient) -> None:
        """Kibana names the saved object it could not load, not the concept."""
        case_id, _ = self._case_with_comment(client)
        answer = client.delete(f"/kibana/api/cases/{case_id}/comments/no-such-comment",
                               headers=self.KBN)
        assert answer.status_code == 404
        assert answer.json()["message"] == (
            "Saved object [cases-comments/no-such-comment] not found")

        missing = client.get("/kibana/api/cases/no-such-case", headers=self.KBN)
        assert missing.json()["message"] == "Saved object [cases/no-such-case] not found"


class TestFalconTellsAClientItsBudget:
    """From ``CrowdStrike/gofalcon``, ``falcon/api_client.go``.

    Its transport takes ``X-Ratelimit-Remaining`` off *every* response and
    keeps it, so a client paces itself before it is ever throttled. On a 429
    it reads ``X-RateLimit-RetryAfter``, which is a **Unix epoch** and not a
    number of seconds — given only the standard `Retry-After`, a Falcon
    client finds nothing it looks for and falls back to its own backoff.

    No other mocked vendor's SDK or connector reads a rate-limit header, so
    no other mount sends one.
    """

    @pytest.fixture
    def throttled(self, client: TestClient) -> dict:
        client.post("/web/api/v2.1/_dev/rate-limit",
                    headers={"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
                    json={"enabled": True, "requestsPerMinute": 3})
        token = client.post("/cs/oauth2/token", data={
            "grant_type": "client_credentials",
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        yield {"Authorization": f"Bearer {token}"}
        client.post("/web/api/v2.1/_dev/rate-limit",
                    headers={"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
                    json={"enabled": False, "requestsPerMinute": 100})

    def test_the_remaining_budget_counts_down(
        self, client: TestClient, throttled: dict,
    ) -> None:
        seen = []
        for _ in range(3):
            answer = client.get("/cs/devices/queries/devices/v1", headers=throttled,
                                params={"limit": 1})
            seen.append(int(answer.headers["x-ratelimit-remaining"]))
        assert seen == [2, 1, 0]

    def test_the_429_names_an_epoch_to_return_at(
        self, client: TestClient, throttled: dict,
    ) -> None:
        for _ in range(3):
            client.get("/cs/devices/queries/devices/v1", headers=throttled,
                       params={"limit": 1})
        answer = client.get("/cs/devices/queries/devices/v1", headers=throttled,
                            params={"limit": 1})
        assert answer.status_code == 429
        assert answer.headers["x-ratelimit-remaining"] == "0"
        # An epoch in the future, not a count of seconds.
        assert int(answer.headers["x-ratelimit-retryafter"]) > time.time()

    def test_no_other_mount_claims_a_budget(
        self, client: TestClient, throttled: dict,
    ) -> None:
        answer = client.get(
            "/web/api/v2.1/agents",
            headers={"Authorization": "ApiToken admin-token-0000-0000-000000000001"},
            params={"limit": 1})
        assert "x-ratelimit-remaining" not in {k.lower() for k in answer.headers}


class TestEachBulkActionDoesWhatItSays:
    """Measured line by line against Elasticsearch 8.15.

    Every line was indexed whatever verb it named: a `create` overwrote the
    document it is meant to refuse to touch, a `delete` wrote instead of
    deleting, an `update` of something absent created it — and `errors` said
    `false` throughout, which is the one field a client checks. Bulk is how
    everything is written at scale, and none of it was.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def _bulk(self, client: TestClient, *lines: str) -> dict:
        return client.post("/elastic/_bulk", headers=self.ES,
                           content="".join(f"{line}\n" for line in lines),
                           params={"refresh": "true"}).json()

    def test_the_whole_action_set(self, client: TestClient) -> None:
        body = self._bulk(
            client,
            '{"index":{"_index":"zzz-bulk","_id":"a"}}', '{"v":1}',
            '{"create":{"_index":"zzz-bulk","_id":"a"}}', '{"v":2}',
            '{"update":{"_index":"zzz-bulk","_id":"a"}}', '{"doc":{"v":3}}',
            '{"update":{"_index":"zzz-bulk","_id":"missing"}}', '{"doc":{"v":9}}',
            '{"delete":{"_index":"zzz-bulk","_id":"a"}}',
            '{"delete":{"_index":"zzz-bulk","_id":"gone"}}',
        )
        seen = [
            (next(iter(item)), next(iter(item.values()))["status"],
             next(iter(item.values())).get("result"),
             (next(iter(item.values())).get("error") or {}).get("type"))
            for item in body["items"]
        ]
        assert seen == [
            ("index", 201, "created", None),
            ("create", 409, None, "version_conflict_engine_exception"),
            ("update", 200, "updated", None),
            ("update", 404, None, "document_missing_exception"),
            ("delete", 200, "deleted", None),
            ("delete", 404, "not_found", None),
        ]
        assert body["errors"] is True

    def test_errors_is_false_when_nothing_failed(self, client: TestClient) -> None:
        body = self._bulk(
            client,
            '{"index":{"_index":"zzz-bulk2","_id":"x"}}', '{"v":1}',
            '{"index":{"_index":"zzz-bulk2","_id":"y"}}', '{"v":2}',
        )
        assert body["errors"] is False

    def test_a_create_leaves_the_document_it_refused_alone(
        self, client: TestClient,
    ) -> None:
        self._bulk(client, '{"index":{"_index":"zzz-bulk3","_id":"k"}}', '{"v":"first"}')
        self._bulk(client, '{"create":{"_index":"zzz-bulk3","_id":"k"}}', '{"v":"second"}')
        got = client.get("/elastic/zzz-bulk3/_doc/k", headers=self.ES).json()
        assert got["_source"]["v"] == "first"

    def test_a_delete_deletes(self, client: TestClient) -> None:
        self._bulk(client, '{"index":{"_index":"zzz-bulk4","_id":"k"}}', '{"v":1}')
        self._bulk(client, '{"delete":{"_index":"zzz-bulk4","_id":"k"}}')
        assert client.get("/elastic/zzz-bulk4/_doc/k",
                          headers=self.ES).status_code == 404

    def test_a_failed_item_carries_an_error_and_no_result(
        self, client: TestClient,
    ) -> None:
        body = self._bulk(
            client, '{"update":{"_index":"zzz-bulk5","_id":"nope"}}', '{"doc":{"v":1}}')
        item = body["items"][0]["update"]
        assert item["status"] == 404
        assert item["error"]["reason"] == "[nope]: document missing"
        assert item["error"]["index"] == "zzz-bulk5"
        assert "_version" not in item

    def test_mget_reports_a_missing_index_per_document(
        self, client: TestClient,
    ) -> None:
        """The `ids` form already said so; the `docs` form did not.

        Reported as `found: false`, a client cannot tell a typo in the index
        name from a document that is genuinely absent.
        """
        client.put("/elastic/zzz-mget/_doc/a", headers=self.ES,
                   params={"refresh": "true"}, json={"v": 1})
        docs = client.post("/elastic/_mget", headers=self.ES, json={"docs": [
            {"_index": "zzz-mget", "_id": "a"},
            {"_index": "zzz-mget", "_id": "nope"},
            {"_index": "zzz-no-such-index", "_id": "x"},
        ]}).json()["docs"]
        assert docs[0]["found"] is True
        assert docs[1]["found"] is False
        assert "found" not in docs[2]
        assert docs[2]["error"]["type"] == "index_not_found_exception"


class TestHidingAHostIsSomethingFalconCanUndo:
    """``hide_host`` "will delete a host"; ``unhide_host`` "will restore a host".

    Falcon's own words, from the four actions its device-actions endpoint
    documents. mockdr dropped the record, so hiding was irreversible — a host
    hidden by mistake could never come back, and
    `/devices/combined/devices-hidden/v1`, the one place a hidden host
    appears, had nothing to list.
    """

    @pytest.fixture
    def cs(self, client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "grant_type": "client_credentials",
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _device(self, client: TestClient, cs: dict) -> str:
        return client.get("/cs/devices/queries/devices/v1", headers=cs,
                          params={"limit": 1}).json()["resources"][0]

    def _act(self, client: TestClient, cs: dict, action: str, device: str) -> object:
        return client.post("/cs/devices/entities/devices-actions/v2", headers=cs,
                           params={"action_name": action}, json={"ids": [device]})

    def test_hidden_then_restored(self, client: TestClient, cs: dict) -> None:
        device = self._device(client, cs)

        def visible() -> int:
            return len(client.post("/cs/devices/entities/devices/v2", headers=cs,
                                   json={"ids": [device]}).json()["resources"])

        def hidden() -> list:
            return client.get("/cs/devices/combined/devices-hidden/v1",
                              headers=cs).json()["resources"]

        assert visible() == 1
        assert self._act(client, cs, "hide_host", device).status_code == 200
        assert visible() == 0
        assert [h["device_id"] for h in hidden()] == [device]

        assert self._act(client, cs, "unhide_host", device).status_code == 200
        assert visible() == 1
        assert hidden() == []

    def test_a_hidden_host_leaves_the_id_listing_too(
        self, client: TestClient, cs: dict,
    ) -> None:
        device = self._device(client, cs)
        self._act(client, cs, "hide_host", device)
        ids = client.get("/cs/devices/queries/devices/v1", headers=cs,
                         params={"limit": 500}).json()["resources"]
        assert device not in ids
        self._act(client, cs, "unhide_host", device)

    def test_the_flag_is_mockdrs_and_stays_out_of_the_answer(
        self, client: TestClient, cs: dict,
    ) -> None:
        """Falcon's device model has no `hidden` property."""
        device = self._device(client, cs)
        record = client.post("/cs/devices/entities/devices/v2", headers=cs,
                             json={"ids": [device]}).json()["resources"][0]
        assert "hidden" not in record

    def test_tagging_is_its_own_route(self, client: TestClient, cs: dict) -> None:
        """``DeviceapiUpdateDeviceTagsRequestV1``: action, device_ids, tags.

        `UpdateDeviceTags` answers one result per device — gofalcon declares
        `resources[*].code`, `.device_id`, `.error` and `.updated` — not the
        device document. Whether the tag took is read from the device.
        """
        device = self._device(client, cs)
        answer = client.patch("/cs/devices/entities/devices/tags/v1", headers=cs,
                              json={"action": "add", "device_ids": [device],
                                    "tags": ["zzz-tag"]})
        assert answer.status_code == 200
        assert answer.json()["resources"] == [
            {"code": 200, "device_id": device, "error": "", "updated": True},
        ]
        assert "zzz-tag" in self._host(client, cs, device)["tags"]

        client.patch("/cs/devices/entities/devices/tags/v1", headers=cs,
                     json={"action": "remove", "device_ids": [device],
                           "tags": ["zzz-tag"]})
        assert "zzz-tag" not in self._host(client, cs, device)["tags"]

    def test_a_device_the_tenant_lacks_is_named_in_the_result(
        self, client: TestClient, cs: dict,
    ) -> None:
        """It used to be skipped in silence, so a 200 covered a typo."""
        answer = client.patch("/cs/devices/entities/devices/tags/v1", headers=cs,
                              json={"action": "add", "device_ids": ["no-such-device"],
                                    "tags": ["zzz-tag"]})
        assert answer.json()["resources"] == [
            {"code": 404, "device_id": "no-such-device",
             "error": "Device not found", "updated": False},
        ]

    @staticmethod
    def _host(client: TestClient, cs: dict, device: str) -> dict:
        return dict(client.post("/cs/devices/entities/devices/v2", headers=cs,
                                json={"ids": [device]}).json()["resources"][0])

    @pytest.mark.parametrize("missing", ["action", "device_ids", "tags"])
    def test_all_three_members_are_required(
        self, client: TestClient, cs: dict, missing: str,
    ) -> None:
        body = {"action": "add", "device_ids": ["x"], "tags": ["y"]}
        del body[missing]
        answer = client.patch("/cs/devices/entities/devices/tags/v1", headers=cs,
                              json=body)
        assert answer.status_code == 400
        assert missing in answer.json()["errors"][0]["message"]

    def test_the_device_actions_endpoint_does_not_tag(
        self, client: TestClient, cs: dict,
    ) -> None:
        """Falcon documents four actions there, and none of them is tagging."""
        device = self._device(client, cs)
        assert self._act(client, cs, "add-hosts", device).status_code == 400


class TestTheKvStoreBatchEndpoints:
    """Measured on Splunk 10.4.2, where both answers were subtly off.

    `batch_find` takes a list of *wrappers* — `{"query": …}` — and mockdr read
    each element itself as the filter, so the documented form matched a field
    called `query` that no record has and came back empty, while an
    undocumented bare filter worked. `batch_save` answers with the keys
    themselves, and mockdr wrapped each in an object.
    """

    C = "/splunk/servicesNS/nobody/search/storage/collections"

    @pytest.fixture
    def collection(self, client: TestClient) -> str:
        client.post(f"{self.C}/config", headers=FORM, params=JSON_OUT,
                    data={"name": "zzz_batch"})
        client.post(f"{self.C}/data/zzz_batch/batch_save", headers=SPLUNK_AUTH,
                    json=[{"_key": "a", "v": 1}, {"_key": "b", "v": 2}])
        return "zzz_batch"

    def test_batch_save_answers_bare_keys(
        self, client: TestClient, collection: str,
    ) -> None:
        answer = client.post(f"{self.C}/data/{collection}/batch_save",
                             headers=SPLUNK_AUTH, json=[{"_key": "c", "v": 3}])
        assert answer.json() == ["c"]

    def test_the_documented_wrapper_filters(
        self, client: TestClient, collection: str,
    ) -> None:
        answer = client.post(f"{self.C}/data/{collection}/batch_find",
                             headers=SPLUNK_AUTH, json=[{"query": {"v": 2}}])
        assert [[r["_key"] for r in group] for group in answer.json()] == [["b"]]

    def test_one_result_set_per_query(
        self, client: TestClient, collection: str,
    ) -> None:
        answer = client.post(f"{self.C}/data/{collection}/batch_find",
                             headers=SPLUNK_AUTH,
                             json=[{"query": {"v": 1}}, {"query": {"v": 2}},
                                   {"query": {"v": 999}}])
        assert [len(group) for group in answer.json()] == [1, 1, 0]

    def test_an_element_without_a_query_matches_everything(
        self, client: TestClient, collection: str,
    ) -> None:
        """splunkd does not error on it; it simply filters by nothing."""
        answer = client.post(f"{self.C}/data/{collection}/batch_find",
                             headers=SPLUNK_AUTH, json=[{"v": 2}])
        assert len(answer.json()[0]) == 2

    def test_an_element_that_is_not_an_object_is_refused(
        self, client: TestClient, collection: str,
    ) -> None:
        answer = client.post(f"{self.C}/data/{collection}/batch_find",
                             headers=SPLUNK_AUTH, params=JSON_OUT, json=["nope"])
        assert answer.status_code == 400
        assert answer.json()["messages"][0]["text"] == "The provided query was invalid."


class TestBulkCreateReportsTheClashItFound:
    """Measured on Kibana 8.15.

    The single-rule route already refused a duplicate `rule_id`; the bulk one
    did not, so an import run twice made a second rule under an id that is
    meant to be unique — and answered as though it had created it.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    @staticmethod
    def _rule(rule_id: str) -> dict:
        return {"name": rule_id, "description": "d", "risk_score": 1,
                "severity": "low", "type": "query", "query": "*:*",
                "index": ["logs-*"], "from": "now-6m", "interval": "5m",
                "rule_id": rule_id}

    def _bulk(self, client: TestClient, *rules: dict) -> list:
        return client.post("/kibana/api/detection_engine/rules/_bulk_create",
                           headers=self.KBN, json=list(rules)).json()

    def test_the_second_import_reports_the_clash(self, client: TestClient) -> None:
        assert "id" in self._bulk(client, self._rule("zzz-bulk-a"))[0]
        again = self._bulk(client, self._rule("zzz-bulk-a"))[0]
        assert again == {
            "rule_id": "zzz-bulk-a",
            "error": {"status_code": 409,
                      "message": 'rule_id: "zzz-bulk-a" already exists'},
        }

    def test_the_rest_of_the_batch_is_still_created(
        self, client: TestClient,
    ) -> None:
        self._bulk(client, self._rule("zzz-bulk-b"))
        results = self._bulk(client, self._rule("zzz-bulk-b"),
                             self._rule("zzz-bulk-c"))
        assert "error" in results[0]
        assert "id" in results[1]

    def test_no_duplicate_rule_id_survives(self, client: TestClient) -> None:
        self._bulk(client, self._rule("zzz-bulk-d"))
        self._bulk(client, self._rule("zzz-bulk-d"))
        found = client.get("/kibana/api/detection_engine/rules/_find",
                           headers=self.KBN, params={"per_page": 200}).json()["data"]
        assert [r["rule_id"] for r in found].count("zzz-bulk-d") == 1


class TestBulkGetIsServedWhereKibanaServesIt:
    """Measured on Kibana 8.15.

    `_bulk_get` is one of the routes Kibana keeps under `/internal`. The mock
    served it under `/api`, where the product answers 404 — so a client using
    the real path got nothing from the mock, and one written against the mock
    got a success the product would not give. The misses are named the way
    the saved-objects layer names them, too.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    def _an_id(self, client: TestClient) -> str:
        found = client.get("/kibana/api/cases/_find", headers=self.KBN,
                           params={"perPage": 1}).json()
        return str(found["cases"][0]["id"])

    def _bulk_get(self, client: TestClient, body: object):
        return client.post("/kibana/internal/cases/_bulk_get",
                           headers=self.KBN, json=body)

    def test_the_public_path_has_no_bulk_get(self, client: TestClient) -> None:
        assert client.post("/kibana/api/cases/_bulk_get", headers=self.KBN,
                           json={"ids": ["x"]}).status_code == 404

    def test_a_miss_is_named_after_the_saved_object(
        self, client: TestClient,
    ) -> None:
        body = self._bulk_get(
            client, {"ids": [self._an_id(client), "no-such-case"]}).json()

        assert len(body["cases"]) == 1
        assert body["errors"] == [{
            "error": "Not Found",
            "message": "Saved object [cases/no-such-case] not found",
            "status": 404,
            "caseId": "no-such-case",
        }]

    def test_ids_must_be_there(self, client: TestClient) -> None:
        response = self._bulk_get(client, {})
        assert response.status_code == 400
        assert response.json()["message"] == (
            'Invalid value "undefined" supplied to "ids"')

    def test_ids_must_not_be_empty(self, client: TestClient) -> None:
        response = self._bulk_get(client, {"ids": []})
        assert response.status_code == 400
        assert response.json()["message"] == (
            "The length of the field ids is too short. "
            "Array must be of length >= 1.")

    def test_ids_must_be_strings(self, client: TestClient) -> None:
        response = self._bulk_get(client, {"ids": [1]})
        assert response.status_code == 400
        assert response.json()["message"] == 'Invalid value "1" supplied to "ids"'

    def test_a_string_body_crashes_the_way_kibana_crashes(
        self, client: TestClient,
    ) -> None:
        response = self._bulk_get(client, {"ids": "x"})
        assert response.status_code == 500
        assert response.json()["message"] == "ids.join is not a function"


class TestARuleCarriesWhatKibanaGivesIt:
    """Measured on Kibana 8.15.

    A rule created with the required fields alone carries none of nine
    optional members; the mock filled all nine in, so a client read a `note`,
    a `throttle` and a timeline the product never mentioned. And the one
    member the product does add — `execution_summary` — the mock never had,
    while accepting a sort over a field inside it.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    #: Absent from a real rule that was created without them.
    OPTIONAL = ["building_block_type", "filters", "investigation_fields",
                "license", "meta", "note", "throttle", "timeline_id",
                "timeline_title"]

    @staticmethod
    def _body(rule_id: str, **extra: object) -> dict:
        return {"name": rule_id, "description": "d", "risk_score": 1,
                "severity": "low", "type": "query", "query": "*:*",
                "index": ["logs-*"], "from": "now-6m", "interval": "5m",
                "rule_id": rule_id, **extra}

    def _create(self, client: TestClient, rule_id: str, **extra: object) -> dict:
        return client.post("/kibana/api/detection_engine/rules",
                           headers=self.KBN,
                           json=self._body(rule_id, **extra)).json()

    def test_an_unset_member_is_not_mentioned(self, client: TestClient) -> None:
        rule = self._create(client, "zzz-plain")
        assert [k for k in self.OPTIONAL if k in rule] == []

    def test_a_member_the_client_set_comes_back(self, client: TestClient) -> None:
        rule = self._create(client, "zzz-noted", note="hi", timeline_id="t-1",
                            timeline_title="T")
        assert rule["note"] == "hi"
        assert rule["timeline_id"] == "t-1"
        assert rule["timeline_title"] == "T"

    def test_an_update_can_add_one(self, client: TestClient) -> None:
        created = self._create(client, "zzz-patched")
        patched = client.patch("/kibana/api/detection_engine/rules",
                               headers=self.KBN,
                               json={"id": created["id"], "note": "later"}).json()
        assert patched["note"] == "later"

    def test_a_rule_that_never_ran_has_no_summary(
        self, client: TestClient,
    ) -> None:
        created = self._create(client, "zzz-never-ran")
        fetched = client.get("/kibana/api/detection_engine/rules",
                             headers=self.KBN,
                             params={"id": created["id"]}).json()
        assert "execution_summary" not in fetched

    def test_a_listing_carries_the_key_for_every_rule(
        self, client: TestClient,
    ) -> None:
        created = self._create(client, "zzz-listed")
        found = client.get("/kibana/api/detection_engine/rules/_find",
                           headers=self.KBN, params={"per_page": 200}).json()

        assert all("execution_summary" in r for r in found["data"])
        mine = [r for r in found["data"] if r["id"] == created["id"]]
        assert mine[0]["execution_summary"] is None

    def test_a_seeded_rule_reports_a_run(self, client: TestClient) -> None:
        found = client.get("/kibana/api/detection_engine/rules/_find",
                           headers=self.KBN, params={"per_page": 200}).json()
        summaries = [r["execution_summary"] for r in found["data"]
                     if r["execution_summary"]]
        assert summaries
        last = summaries[0]["last_execution"]
        assert set(last) == {"date", "status", "status_order", "message",
                             "metrics"}

    def test_sorting_by_the_nested_execution_date_orders_the_list(
        self, client: TestClient,
    ) -> None:
        found = client.get(
            "/kibana/api/detection_engine/rules/_find", headers=self.KBN,
            params={"per_page": 200, "sort_field":
                    "execution_summary.last_execution.date",
                    "sort_order": "desc"}).json()["data"]
        dates = [(r["execution_summary"] or {}).get("last_execution", {}).get("date", "")
                 for r in found]
        assert dates == sorted(dates, reverse=True)
        assert any(dates)


class TestWhatAWriteCountsAsAChange:
    """Measured on Kibana 8.15.

    Two counters, and the mock moved the wrong one. `version` is the author's
    and only ever changes because a client set it; `revision` is Kibana's own
    modification counter and stood still at 0. And PATCH — the call a client
    makes to change one member — had no route at all, so the only way to
    change anything was a PUT that reset everything left out.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    @staticmethod
    def _body(rule_id: str, **extra: object) -> dict:
        return {"name": rule_id, "description": "d", "risk_score": 1,
                "severity": "low", "type": "query", "query": "*:*",
                "index": ["logs-*"], "from": "now-6m", "interval": "5m",
                "rule_id": rule_id, **extra}

    def _create(self, client: TestClient, rule_id: str, **extra: object) -> dict:
        return client.post("/kibana/api/detection_engine/rules",
                           headers=self.KBN,
                           json=self._body(rule_id, **extra)).json()

    def _patch(self, client: TestClient, body: dict):
        return client.patch("/kibana/api/detection_engine/rules",
                            headers=self.KBN, json=body)

    def test_a_new_rule_starts_at_revision_zero(self, client: TestClient) -> None:
        created = self._create(client, "zzz-rev-new", version=9)
        assert created["revision"] == 0
        assert created["version"] == 9

    def test_a_real_change_raises_the_revision(self, client: TestClient) -> None:
        self._create(client, "zzz-rev-change")
        patched = self._patch(
            client, {"rule_id": "zzz-rev-change", "description": "other"}).json()
        assert patched["revision"] == 1
        assert patched["version"] == 1

    def test_the_same_value_again_is_not_a_change(
        self, client: TestClient,
    ) -> None:
        self._create(client, "zzz-rev-same")
        self._patch(client, {"rule_id": "zzz-rev-same", "description": "other"})
        again = self._patch(
            client, {"rule_id": "zzz-rev-same", "description": "other"}).json()
        assert again["revision"] == 1

    def test_enabling_a_rule_is_not_a_change(self, client: TestClient) -> None:
        self._create(client, "zzz-rev-toggle", enabled=False)
        patched = self._patch(
            client, {"rule_id": "zzz-rev-toggle", "enabled": True}).json()
        assert patched["enabled"] is True
        assert patched["revision"] == 0

    def test_setting_the_version_is_a_change(self, client: TestClient) -> None:
        self._create(client, "zzz-rev-version")
        patched = self._patch(
            client, {"rule_id": "zzz-rev-version", "version": 42}).json()
        assert patched["version"] == 42
        assert patched["revision"] == 1

    def test_a_patch_leaves_everything_it_does_not_name(
        self, client: TestClient,
    ) -> None:
        self._create(client, "zzz-patch-keeps", note="keep me", tags=["t"])
        patched = self._patch(
            client, {"rule_id": "zzz-patch-keeps", "severity": "high"}).json()
        assert patched["severity"] == "high"
        assert patched["note"] == "keep me"
        assert patched["tags"] == ["t"]

    def test_a_put_drops_what_the_body_leaves_out(
        self, client: TestClient,
    ) -> None:
        self._create(client, "zzz-put-drops", note="gone soon", tags=["t"])
        replaced = client.put("/kibana/api/detection_engine/rules",
                              headers=self.KBN,
                              json=self._body("zzz-put-drops")).json()
        assert "note" not in replaced
        assert replaced["tags"] == []

    def test_a_put_keeps_the_authored_version_and_the_enabled_flag(
        self, client: TestClient,
    ) -> None:
        self._create(client, "zzz-put-keeps", version=7, enabled=False)
        replaced = client.put("/kibana/api/detection_engine/rules",
                              headers=self.KBN,
                              json=self._body("zzz-put-keeps")).json()
        assert replaced["version"] == 7
        assert replaced["enabled"] is False

    def test_either_identifier_addresses_the_rule(
        self, client: TestClient,
    ) -> None:
        created = self._create(client, "zzz-addressed")
        by_id = self._patch(client, {"id": created["id"], "severity": "high"})
        by_rule_id = self._patch(
            client, {"rule_id": "zzz-addressed", "severity": "medium"})
        assert by_id.status_code == 200
        assert by_rule_id.json()["severity"] == "medium"

    def test_neither_identifier_is_a_400(self, client: TestClient) -> None:
        response = self._patch(client, {"severity": "high"})
        assert response.status_code == 400
        assert response.json()["message"] == ['either "id" or "rule_id" must be set']

    def test_an_unknown_identifier_is_named_in_the_404(
        self, client: TestClient,
    ) -> None:
        response = self._patch(client, {"rule_id": "no-such-rule"})
        assert response.status_code == 404
        assert response.json() == {
            "message": 'rule_id: "no-such-rule" not found', "status_code": 404}


class TestAnExceptionItemIsChecked:
    """Measured on Kibana 8.15, twenty error paths compared byte for byte.

    Nothing was checked here at all: an empty body created an item, a body
    naming a list that does not exist created one on that list, and a client
    was told each time that it had succeeded. An exception with no entries
    matches nothing, so a rule carrying it behaves as though the exception
    were not there — and the client had been told it was.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    ENTRY = {"field": "a", "operator": "included", "type": "match", "value": "b"}

    def _list_id(self, client: TestClient) -> str:
        found = client.get("/kibana/api/exception_lists/_find", headers=self.KBN,
                           params={"per_page": 1}).json()
        return str(found["data"][0]["list_id"])

    def _item(self, client: TestClient, **extra: object) -> dict:
        body = {"list_id": self._list_id(client), "name": "n", "description": "d",
                "type": "simple", "entries": [self.ENTRY]}
        body.update(extra)
        return body

    def _post(self, client: TestClient, body: dict):
        return client.post("/kibana/api/exception_lists/items",
                           headers=self.KBN, json=body)

    def test_an_empty_body_names_every_member_it_wanted(
        self, client: TestClient,
    ) -> None:
        response = self._post(client, {})
        assert response.status_code == 400
        assert response.json()["message"] == (
            '[request body]: Invalid value "undefined" supplied to "description",'
            'Invalid value "undefined" supplied to "entries",'
            'Invalid value "undefined" supplied to "list_id",'
            'Invalid value "undefined" supplied to "name",'
            'Invalid value "undefined" supplied to "type"')

    def test_a_list_that_does_not_exist(self, client: TestClient) -> None:
        response = self._post(client, self._item(client, list_id="no-such-list"))
        assert response.status_code == 404
        assert response.json() == {
            "message": 'exception list id: "no-such-list" does not exist',
            "status_code": 404}

    def test_a_member_the_codec_has_no_definition_for(
        self, client: TestClient,
    ) -> None:
        response = self._post(client, self._item(client, nonsense_member=1))
        assert response.status_code == 400
        assert response.json()["message"] == (
            '[request body]: invalid keys "nonsense_member"')

    def test_an_entry_reports_every_branch_of_the_union(
        self, client: TestClient,
    ) -> None:
        """An entry is a union, and io-ts reports each branch it tried."""
        response = self._post(client, self._item(client, entries=[{"nope": 1}]))
        assert response.json()["message"] == (
            '[request body]: Invalid value "undefined" supplied to "entries,field",'
            'Invalid value "undefined" supplied to "entries,operator",'
            'Invalid value "undefined" supplied to "entries,type",'
            'Invalid value "undefined" supplied to "entries,value",'
            'Invalid value "undefined" supplied to "entries,list",'
            'Invalid value "undefined" supplied to "entries,entries"')

    def test_an_operator_kibana_does_not_have(self, client: TestClient) -> None:
        response = self._post(client, self._item(client, 
            entries=[{"field": "a", "operator": "is", "type": "match",
                      "value": "b"}]))
        assert response.status_code == 400
        assert response.json()["message"].startswith(
            '[request body]: Invalid value "is" supplied to "entries,operator"')

    def test_a_match_any_entry_is_a_branch_of_its_own(
        self, client: TestClient,
    ) -> None:
        ok = self._post(client, self._item(client, 
            item_id="zzz-any",
            entries=[{"field": "a", "operator": "included", "type": "match_any",
                      "value": ["b"]}]))
        assert ok.status_code == 200

    def test_the_seeded_items_are_ones_kibana_would_accept(
        self, client: TestClient,
    ) -> None:
        """The fixture used an operator no Kibana emits.

        A client reading mockdr's exceptions saw `is`, and writing one back
        the way it was read is exactly what a 400 answers.
        """
        found = client.get(
            "/kibana/api/exception_lists/items/_find", headers=self.KBN,
            params={"list_id": self._list_id(client), "per_page": 100},
        ).json()["data"]
        assert found
        operators = {e["operator"] for item in found for e in item["entries"]}
        assert operators <= {"included", "excluded"}

    def test_a_duplicate_item_id(self, client: TestClient) -> None:
        self._post(client, self._item(client, item_id="zzz-dup"))
        again = self._post(client, self._item(client, item_id="zzz-dup"))
        assert again.status_code == 409
        assert again.json() == {
            "message": 'exception list item id: "zzz-dup" already exists',
            "status_code": 409}

    def test_an_update_naming_no_item_is_a_404(self, client: TestClient) -> None:
        response = client.put("/kibana/api/exception_lists/items",
                              headers=self.KBN,
                              json={"name": "n", "description": "d",
                                    "type": "simple", "entries": [self.ENTRY]})
        assert response.status_code == 404
        assert response.json() == {
            "message": "either id or item_id need to be defined",
            "status_code": 404}

    def test_a_listing_without_a_list_is_refused(
        self, client: TestClient,
    ) -> None:
        """It used to answer with every item across every list."""
        response = client.get("/kibana/api/exception_lists/items/_find",
                              headers=self.KBN)
        assert response.status_code == 400
        assert response.json()["message"] == (
            '[request query]: Invalid value "undefined" supplied to "list_id"')

    def test_a_missing_item_is_named_by_the_id_that_addressed_it(
        self, client: TestClient,
    ) -> None:
        by_item_id = client.get("/kibana/api/exception_lists/items",
                                headers=self.KBN, params={"item_id": "nope"})
        by_id = client.get("/kibana/api/exception_lists/items",
                           headers=self.KBN, params={"id": "nope"})
        assert by_item_id.json()["message"] == (
            'exception list item item_id: "nope" does not exist')
        assert by_id.json()["message"] == (
            'exception list item id: "nope" does not exist')

    def test_the_two_missing_argument_messages_are_not_the_same(
        self, client: TestClient,
    ) -> None:
        """Kibana words them differently, and a client matching on one of them
        must not find the other."""
        read = client.get("/kibana/api/exception_lists/items", headers=self.KBN)
        removed = client.request("DELETE", "/kibana/api/exception_lists/items",
                                 headers=self.KBN)
        assert read.json()["message"] == "id or item_id required"
        assert removed.json()["message"] == (
            'Either "item_id" or "id" needs to be defined in the request')


class TestAWriteRouteReadsTheBodyItDeclares:
    """Measured on Elasticsearch 8.15 and Kibana 8.15.

    Found by asking every route that declares a body what it does with one
    that cannot be what it meant — an empty object, and an object with one
    member the route never declared. Five routes answered 200 to both.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}
    KBN = {**ES, "kbn-xsrf": "true"}

    def test_aliases_with_nothing_to_do(self, client: TestClient) -> None:
        """A client whose own filter matched nothing built an empty action
        list, and was told the aliases had been updated."""
        for body in ({}, {"actions": []}):
            response = client.post("/elastic/_aliases", headers=self.ES, json=body)
            assert response.status_code == 400
            assert response.json()["error"]["reason"] == "No action specified"

    def test_aliases_with_a_member_it_does_not_know(
        self, client: TestClient,
    ) -> None:
        response = client.post("/elastic/_aliases", headers=self.ES,
                               json={"zzz_undeclared_member": 1})
        assert response.status_code == 400
        assert response.json()["error"] == {
            "root_cause": [{
                "type": "x_content_parse_exception",
                "reason": "[1:2] [aliases] unknown field [zzz_undeclared_member]",
            }],
            "type": "x_content_parse_exception",
            "reason": "[1:2] [aliases] unknown field [zzz_undeclared_member]",
        }

    def test_count_takes_a_query_and_nothing_else(
        self, client: TestClient,
    ) -> None:
        """`size` and `aggs` belong to the neighbouring `_search`, and a
        client reusing a search body here was counted with them dropped."""
        assert client.post("/elastic/_count", headers=self.ES,
                           json={"query": {"match_all": {}}}).status_code == 200
        for key in ("size", "aggs", "from", "min_score"):
            response = client.post("/elastic/_count", headers=self.ES,
                                   json={key: 1})
            assert response.status_code == 400
            assert response.json()["error"] == {
                "root_cause": [{
                    "type": "parsing_exception",
                    "reason": f"request does not support [{key}]",
                    "line": 1, "col": 2,
                }],
                "type": "parsing_exception",
                "reason": f"request does not support [{key}]",
                "line": 1, "col": 2,
            }

    def test_an_export_says_what_to_export(self, client: TestClient) -> None:
        response = client.post("/kibana/api/detection_engine/rules/_export",
                               headers=self.KBN, json={})
        assert response.status_code == 400
        assert response.json()["message"] == "[request body]: objects: Required"

    def test_an_empty_selection_exports_nothing(
        self, client: TestClient,
    ) -> None:
        """It used to export every rule mockdr held."""
        text = client.post("/kibana/api/detection_engine/rules/_export",
                           headers=self.KBN, json={"objects": []}).text
        summary = json.loads(text.strip().split("\n")[-1])
        assert summary["exported_count"] == 0

    def test_a_rule_the_export_could_not_find_is_listed(
        self, client: TestClient,
    ) -> None:
        text = client.post(
            "/kibana/api/detection_engine/rules/_export", headers=self.KBN,
            json={"objects": [{"rule_id": "no-such-rule"}]}).text
        summary = json.loads(text.strip().split("\n")[-1])
        assert summary["missing_rules"] == [{"rule_id": "no-such-rule"}]
        assert summary["missing_rules_count"] == 1
        assert summary["excluded_action_connections"] == []

    def test_suggestions_need_a_field_to_suggest_for(
        self, client: TestClient,
    ) -> None:
        """It used to answer with every hostname it held."""
        response = client.post("/kibana/api/endpoint/suggestions/eventFilters",
                               headers=self.KBN, json={})
        assert response.status_code == 400
        assert response.json()["message"] == (
            "[request body.field]: expected value of type [string] "
            "but got [undefined]")

    def test_suggestions_with_a_field_answer(self, client: TestClient) -> None:
        response = client.post("/kibana/api/endpoint/suggestions/eventFilters",
                               headers=self.KBN,
                               json={"field": "host.os.name", "query": ""})
        assert response.status_code == 200
        assert isinstance(response.json(), list)


class TestASentinelOneWriteBodyIsRecognisable:
    """From the 2.1 swagger, which says what each write body is made of.

    Twenty-five write routes answered 200 to `{}` — a threat marked as an
    incident with no verdict, an exclusion created out of nothing, a policy
    replaced by an empty document. Each reported success, which leaves the
    client believing the write happened the way it asked.

    The guard refuses a body carrying *nothing the route knows*. It does not
    decide which combination is enough: the swagger says `data` is required
    for `/threats/analyst-verdict`, and whether real S1 also takes the flat
    form is not something the reference states, so both are let through.
    """

    S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

    def test_an_empty_body_is_refused(self, client: TestClient) -> None:
        response = client.post("/web/api/v2.1/threats/analyst-verdict",
                               headers=self.S1, json={})
        assert response.status_code == 400
        error = response.json()["errors"][0]
        assert error["title"] == "Validation Error"
        assert error["code"] == 4000010
        assert "analystVerdict" in error["detail"]

    def test_a_body_of_undeclared_members_is_refused(
        self, client: TestClient,
    ) -> None:
        assert client.post("/web/api/v2.1/threats/analyst-verdict",
                           headers=self.S1,
                           json={"zzz_undeclared_member": 1}).status_code == 400

    def test_the_documented_body_is_taken(self, client: TestClient) -> None:
        response = client.post(
            "/web/api/v2.1/threats/analyst-verdict", headers=self.S1,
            json={"data": {"analystVerdict": "true_positive"},
                  "filter": {"ids": ["1"]}})
        assert response.status_code == 200

    def test_the_flat_form_this_mock_also_takes_is_still_a_body(
        self, client: TestClient,
    ) -> None:
        assert client.post("/web/api/v2.1/threats/analyst-verdict",
                           headers=self.S1,
                           json={"analystVerdict": "true_positive"}
                           ).status_code == 200

    def test_a_route_that_takes_no_body_is_left_alone(
        self, client: TestClient,
    ) -> None:
        """The swagger marks `data` required on routes with no document —
        reactivating a site, for one — and requiring a body there would
        invent a rule rather than enforce a documented one."""
        site_id = client.get("/web/api/v2.1/sites", headers=self.S1
                             ).json()["data"]["sites"][0]["id"]
        assert client.put(f"/web/api/v2.1/sites/{site_id}/reactivate",
                          headers=self.S1).status_code == 200

    def test_authorisation_is_decided_before_the_body(
        self, client: TestClient,
    ) -> None:
        """A caller without the right to write must not learn what the body
        should have looked like."""
        viewer = {"Authorization": "ApiToken viewer-token-0000-0000-000000000002"}
        response = client.post("/web/api/v2.1/threat-intelligence/iocs",
                               headers=viewer,
                               json={"type": "IPV4", "value": "1.2.3.4"})
        assert response.status_code == 403


class TestTheAgentActionsFalconsRivalPublishes:
    """From the 2.1 swagger, which publishes one path per agent action.

    mockdr answered 400 to half of them — a client could not run the actions
    its own console offers, and the 400 said the request had been understood
    and rejected rather than never offered. The ones that leave a mark on the
    agent record now leave it; the rest count and log, which is all the
    record shows for a broadcast either.
    """

    S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

    def _agent_id(self, client: TestClient) -> str:
        return str(client.get("/web/api/v2.1/agents", headers=self.S1,
                              params={"limit": 1}).json()["data"][0]["id"])

    def _act(self, client: TestClient, action: str, agent_id: str):
        return client.post(f"/web/api/v2.1/agents/actions/{action}",
                           headers=self.S1, json={"filter": {"ids": [agent_id]}})

    def _agent(self, client: TestClient, agent_id: str) -> dict:
        return dict(client.get("/web/api/v2.1/agents", headers=self.S1,
                               params={"ids": agent_id}).json()["data"][0])

    @pytest.mark.parametrize(("action", "field", "expected"), [
        ("ranger-disable", "rangerStatus", "Disabled"),
        ("ranger-enable", "rangerStatus", "Enabled"),
        ("start-profiling", "remoteProfilingState", "enabled"),
        ("stop-profiling", "remoteProfilingState", "disabled"),
        ("update-software", "isUpToDate", True),
        ("reject-uninstall", "isPendingUninstall", False),
    ])
    def test_the_action_moves_what_it_says(
        self, client: TestClient, action: str, field: str, expected: object,
    ) -> None:
        agent_id = self._agent_id(client)
        assert self._act(client, action, agent_id).status_code == 200
        assert self._agent(client, agent_id)[field] == expected

    def test_approving_an_uninstall_carries_it_out(
        self, client: TestClient,
    ) -> None:
        agent_id = self._agent_id(client)
        self._act(client, "uninstall", agent_id)
        assert self._agent(client, agent_id)["isPendingUninstall"] is True

        self._act(client, "approve-uninstall", agent_id)
        after = self._agent(client, agent_id)
        assert after["isPendingUninstall"] is False
        assert after["isUninstalled"] is True

    @pytest.mark.parametrize("action", [
        "set-config", "start-remote-shell", "terminate-remote-shell",
        "firewall-logging", "reset-passphrase", "approve-stateless-upgrade",
    ])
    def test_an_action_with_nothing_to_show_still_runs(
        self, client: TestClient, action: str,
    ) -> None:
        response = self._act(client, action, self._agent_id(client))
        assert response.status_code == 200
        assert response.json()["data"]["affected"] == 1

    def test_a_name_that_is_not_an_action_is_a_missing_path(
        self, client: TestClient,
    ) -> None:
        response = self._act(client, "zzz-not-an-action", self._agent_id(client))
        assert response.status_code == 404
        assert response.json()["errors"][0]["detail"] == (
            "Resource not found: POST /web/api/v2.1/agents/actions/zzz-not-an-action")


class TestAFalconWriteBodyIsRecognisable:
    """From gofalcon's `request_required`, the same question as SentinelOne's.

    Six Falcon write routes answered 200 to `{}`: a host action addressed to
    no host, an indicator create with no indicators, a case tagged with
    nothing. Each came back as a success with an empty `resources` list,
    which reads exactly like a request that matched nothing.
    """

    def _auth(self, client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "grant_type": "client_credentials",
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.parametrize("path", [
        "/cs/devices/entities/devices/v2",
        "/cs/iocs/entities/indicators/v1",
        "/cs/cases/entities/case-tags/v1",
        "/cs/quarantine/entities/quarantined-files/GET/v1",
    ])
    def test_an_empty_body_is_refused(
        self, client: TestClient, path: str,
    ) -> None:
        response = client.post(path, headers=self._auth(client), json={})
        assert response.status_code == 400
        assert response.json()["errors"][0]["code"] == 400

    def test_the_documented_body_is_taken(self, client: TestClient) -> None:
        response = client.post("/cs/devices/entities/devices/v2",
                               headers=self._auth(client), json={"ids": ["x"]})
        assert response.status_code == 200

    def test_the_error_wears_falcons_envelope(self, client: TestClient) -> None:
        body = client.post("/cs/devices/entities/devices/v2",
                           headers=self._auth(client), json={}).json()
        assert body["resources"] == []
        assert "trace_id" in body["meta"]

    def test_the_alerts_route_still_takes_the_older_spelling(
        self, client: TestClient,
    ) -> None:
        """`composite_ids` is the v3 name; the handler reads `ids` as well,
        and this check exists to refuse a body that says nothing — not to
        withdraw what the mock already answers to."""
        response = client.post("/cs/alerts/entities/alerts/v2",
                               headers=self._auth(client),
                               json={"ids": ["ldt:x:1"]})
        assert response.status_code == 200


class TestACortexWriteBodyIsRecognisable:
    """From the community transcription of the Cortex reference.

    Most Cortex routes require nothing at all — `xql/get_quota` gives
    `{"request_data": null}` as its own example — so most of them are right
    to answer an empty body. The ones whose reference does state a
    requirement were answering it too: quarantine status for no files,
    a user group lookup for no group.
    """

    XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}

    def test_a_route_that_states_a_requirement_refuses_nothing(
        self, client: TestClient,
    ) -> None:
        response = client.post("/xdr/public_api/v1/quarantine/status/",
                               headers=self.XDR, json={})
        assert response.status_code == 400
        assert response.json()["reply"]["err_code"] == 400

    def test_the_wrapper_is_all_it_asks_for(self, client: TestClient) -> None:
        response = client.post("/xdr/public_api/v1/quarantine/status/",
                               headers=self.XDR,
                               json={"request_data": {"files": []}})
        assert response.status_code == 200

    @pytest.mark.parametrize("path", [
        "/xdr/public_api/v1/rbac/get_roles/",
        "/xdr/public_api/v1/system/get_tenant_info/",
        "/xdr/public_api/v1/xql/get_quota",
    ])
    def test_a_route_that_states_no_requirement_still_answers(
        self, client: TestClient, path: str,
    ) -> None:
        """Refusing these would invent a rule the reference does not state."""
        assert client.post(path, headers=self.XDR, json={}).status_code == 200

    def test_the_refusal_wears_cortex_own_envelope(
        self, client: TestClient,
    ) -> None:
        body = client.post("/xdr/public_api/v1/rbac/get_user_group/",
                           headers=self.XDR, json={}).json()
        assert set(body["reply"]) == {"err_code", "err_msg", "err_extra"}


class TestPollingACortexActionFinds:
    """From `xsoar-samples/*/action_status_get.json`, recorded off the product.

    Cortex answers `get_action_status` as a map from endpoint id to status —
    which is what a playbook polls: it isolates an endpoint and waits for
    that endpoint's key to say `COMPLETED_SUCCESSFULLY`. mockdr answered with
    the action's own record, completed against the recording, so every reply
    carried the same three endpoints from someone else's install and the one
    the client had just acted on was never among them. The wait never ended.
    """

    XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}

    def _endpoint_id(self, client: TestClient) -> str:
        found = client.post("/xdr/public_api/v1/endpoints/get_endpoint/",
                            headers=self.XDR, json={"request_data": {}}).json()
        return str(found["reply"]["endpoints"][0]["endpoint_id"])

    def _isolate(self, client: TestClient, endpoint_id: str) -> str:
        reply = client.post("/xdr/public_api/v1/endpoints/isolate/",
                            headers=self.XDR,
                            json={"request_data": {"endpoint_id": endpoint_id}})
        return str(reply.json()["reply"]["action_id"])

    def _status(self, client: TestClient, action_id: str) -> dict:
        return dict(client.post(
            "/xdr/public_api/v1/actions/get_action_status/", headers=self.XDR,
            json={"request_data": {"group_action_id": action_id}},
        ).json()["reply"])

    def test_the_endpoint_acted_on_is_the_one_reported(
        self, client: TestClient,
    ) -> None:
        endpoint_id = self._endpoint_id(client)
        reply = self._status(client, self._isolate(client, endpoint_id))
        assert list(reply["data"]) == [endpoint_id]

    def test_nobody_elses_endpoints_are_in_the_answer(
        self, client: TestClient,
    ) -> None:
        """The recording's three endpoint ids used to be in every reply."""
        reply = self._status(client, self._isolate(client, self._endpoint_id(client)))
        assert "aeec6a2cc92e46fab3b6f621722e9916" not in reply["data"]

    def test_the_status_is_spelled_the_way_cortex_spells_it(
        self, client: TestClient,
    ) -> None:
        reply = self._status(client, self._isolate(client, self._endpoint_id(client)))
        assert set(reply["data"].values()) == {"COMPLETED_SUCCESSFULLY"}

    def test_polling_an_action_nobody_started(self, client: TestClient) -> None:
        response = client.post(
            "/xdr/public_api/v1/actions/get_action_status/", headers=self.XDR,
            json={"request_data": {"group_action_id": "no-such-action"}})
        assert response.status_code == 500
        assert response.json()["reply"]["err_extra"] == (
            "Action no-such-action not found")

    def test_only_a_failure_carries_a_reason(self, client: TestClient) -> None:
        """`errorReasons` is keyed by the endpoints that failed, and is
        absent when none did."""
        from repository.xdr_action_repo import xdr_action_repo

        replies = [self._status(client, a.action_id)
                   for a in xdr_action_repo.list_all()]
        for reply in replies:
            failed = [e for e, s in reply["data"].items() if s == "FAILED"]
            assert list(reply.get("errorReasons", {})) == failed

    def test_a_client_only_ever_sees_a_status_the_product_spells(
        self, client: TestClient,
    ) -> None:
        from repository.xdr_action_repo import xdr_action_repo

        seen = {
            status
            for action in xdr_action_repo.list_all()
            for status in self._status(client, action.action_id)["data"].values()
        }
        assert seen <= {"COMPLETED_SUCCESSFULLY", "FAILED"}


class TestBothSpellingsOfACortexPath:
    """Cortex paths are written both ways in the wild.

    The community transcription of the reference spells them without a
    trailing slash, connector code with one — and mockdr served forty-five of
    its fifty-one XDR routes with the slash and six without, refusing the
    other spelling with a 404. A client keeping to either convention hit a
    wall on some routes.
    """

    XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}

    @pytest.mark.parametrize("path", [
        "/xdr/public_api/v1/rbac/get_roles",
        "/xdr/public_api/v1/xql/get_quota",
        "/xdr/public_api/v1/system/get_tenant_info",
    ])
    def test_either_spelling_reaches_the_route(
        self, client: TestClient, path: str,
    ) -> None:
        for candidate in (path, path + "/"):
            response = client.post(candidate, headers=self.XDR,
                                   json={"request_data": {}})
            assert response.status_code == 200, candidate

    def test_the_alias_is_not_a_second_published_route(
        self, client: TestClient,
    ) -> None:
        """The published surface still names one path per route."""
        from main import app

        paths = app.openapi()["paths"]
        assert "/xdr/public_api/v1/rbac/get_roles" not in paths
        assert "/xdr/public_api/v1/rbac/get_roles/" in paths

    def test_the_alias_still_wants_credentials(self, client: TestClient) -> None:
        assert client.post("/xdr/public_api/v1/rbac/get_roles",
                           json={"request_data": {}}).status_code == 401


class TestAnActionThatSettles:
    """Three products, one class of defect: a state that never left `pending`.

    A playbook contains a host, isolates an endpoint, and then waits for the
    action to finish. Falcon's host stayed `containment_pending` for ever,
    Kibana's action stayed `pending` with no `completed_at`, and
    `/api/endpoint/action_status` — which counts what is pending per agent —
    only ever counted upwards. Each settles now once the sensor has had time
    to answer, which is also what makes the pending state worth observing.
    """

    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    def _falcon(self, client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "grant_type": "client_credentials",
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _host_status(self, client: TestClient, headers: dict, host_id: str) -> str:
        found = client.post("/cs/devices/entities/devices/v2", headers=headers,
                            json={"ids": [host_id]}).json()
        return str(found["resources"][0]["status"])

    def _a_normal_host(self, client: TestClient, headers: dict) -> str:
        ids = client.get("/cs/devices/queries/devices/v1", headers=headers,
                         params={"limit": 50}).json()["resources"]
        found = client.post("/cs/devices/entities/devices/v2", headers=headers,
                            json={"ids": ids}).json()["resources"]
        return str(next(h["device_id"] for h in found if h["status"] == "normal"))

    def _act(self, client: TestClient, headers: dict, host_id: str, action: str) -> None:
        client.post("/cs/devices/entities/devices-actions/v2", headers=headers,
                    params={"action_name": action}, json={"ids": [host_id]})

    def test_containment_settles(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        headers = self._falcon(client)
        host_id = self._a_normal_host(client, headers)

        # Held open, then closed, rather than raced: on a loaded runner the
        # second between the write and the read is not reliably a second.
        monkeypatch.setattr(host_queries, "_SETTLE_SECONDS", 3600.0)
        self._act(client, headers, host_id, "contain")
        assert self._host_status(client, headers, host_id) == "containment_pending"

        monkeypatch.setattr(host_queries, "_SETTLE_SECONDS", 0.0)
        assert self._host_status(client, headers, host_id) == "contained"

    def test_lifting_containment_settles_too(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        headers = self._falcon(client)
        host_id = self._a_normal_host(client, headers)

        monkeypatch.setattr(host_queries, "_SETTLE_SECONDS", 3600.0)
        self._act(client, headers, host_id, "contain")
        self._act(client, headers, host_id, "lift_containment")
        assert self._host_status(client, headers, host_id) == (
            "lift_containment_pending")

        monkeypatch.setattr(host_queries, "_SETTLE_SECONDS", 0.0)
        assert self._host_status(client, headers, host_id) == "normal"

    def _agent(self, client: TestClient) -> str:
        listing = client.get("/kibana/api/endpoint/metadata",
                             headers=self.KBN).json()
        return str(listing["data"][0]["metadata"]["agent"]["id"])

    def test_an_isolation_finishes(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = self._agent(client)
        # Hold the window open rather than racing it: a loaded runner spent
        # more than the settle second between the write and the read, and
        # read back an action that had already finished.
        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 3600.0)
        action = client.post("/kibana/api/endpoint/action/isolate",
                             headers=self.KBN,
                             json={"endpoint_ids": [agent], "comment": "x"}).json()
        assert action["status"] == "pending"
        assert action["completed_at"] is None

        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 0.0)
        settled = client.get(f"/kibana/api/endpoint/action/{action['id']}",
                             headers=self.KBN).json()
        assert settled["status"] == "successful"
        assert settled["completed_at"]

    def test_the_status_is_one_kibana_validates(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Measured on 8.15: `statuses` takes `failed`, `pending` and
        `successful`, and refuses anything else."""
        agent = self._agent(client)
        client.post("/kibana/api/endpoint/action/isolate", headers=self.KBN,
                    json={"endpoint_ids": [agent], "comment": "x"})
        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 0.0)
        listing = client.get("/kibana/api/endpoint/action", headers=self.KBN).json()
        assert {a["status"] for a in listing["data"]} <= {
            "failed", "pending", "successful"}

    def test_what_is_pending_stops_being_pending(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """`action_status` counted upwards for ever."""
        agent = self._agent(client)
        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 3600.0)
        client.post("/kibana/api/endpoint/action/isolate", headers=self.KBN,
                    json={"endpoint_ids": [agent], "comment": "x"})
        pending = client.get("/kibana/api/endpoint/action_status",
                             headers=self.KBN,
                             params={"agent_ids": agent}).json()["data"][0]
        assert pending["pending_actions"].get("isolate", 0) >= 1

        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 0.0)
        settled = client.get("/kibana/api/endpoint/action_status",
                             headers=self.KBN,
                             params={"agent_ids": agent}).json()["data"][0]
        assert settled["pending_actions"] == {}


class TestSortingByWhatTheVendorDocuments:
    """From the 2.1 swagger's own `sortBy` enum.

    Fifteen documented sort fields were accepted and ignored, because the
    records keep them one level down — a threat's `createdAt` lives in
    `threatInfo`, its `agentVersion` in `agentDetectionInfo` — and the
    sorter only looked at the top level. Every key compared equal, so
    `sortOrder=asc` came back identical to `desc`: a client that asked for
    an order got whatever order the store held, and was told nothing.
    """

    S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

    def _both_ways(self, client: TestClient, path: str, field: str):
        pages = []
        for order in ("asc", "desc"):
            pages.append(client.get(path, headers=self.S1, params={
                "limit": 50, "sortBy": field, "sortOrder": order,
            }).json()["data"])
        return pages

    @pytest.mark.parametrize("field", [
        "createdAt", "updatedAt", "agentVersion", "agentMachineType",
        "siteId", "siteName", "agentComputerName", "filePath",
        "collectionId", "classification",
    ])
    def test_a_threat_sort_field_orders_the_list(
        self, client: TestClient, field: str,
    ) -> None:
        ascending, descending = self._both_ways(
            client, "/web/api/v2.1/threats", field)
        assert ascending != descending

    @pytest.mark.parametrize("field", [
        "machineType", "osName", "incidentStatus", "analystVerdict", "severity",
    ])
    def test_a_cloud_alert_sort_field_orders_the_list(
        self, client: TestClient, field: str,
    ) -> None:
        ascending, descending = self._both_ways(
            client, "/web/api/v2.1/cloud-detection/alerts", field)
        assert ascending != descending

    def test_the_order_is_the_one_asked_for(self, client: TestClient) -> None:
        ascending, descending = self._both_ways(
            client, "/web/api/v2.1/threats", "createdAt")
        dates = [t["threatInfo"]["createdAt"] for t in ascending]
        assert dates == sorted(dates)
        assert [t["threatInfo"]["createdAt"] for t in descending] == sorted(
            dates, reverse=True)

    def test_a_name_the_records_do_not_carry_leaves_the_order_alone(
        self, client: TestClient,
    ) -> None:
        """Rather than reordering by nothing."""
        ascending, descending = self._both_ways(
            client, "/web/api/v2.1/threats", "zzz-no-such-field")
        assert ascending == descending


class TestARefusedBearerRequestSaysWhereToGetOne:
    """RFC 6750 §3, which every OAuth mount here ignored.

    A resource server that refuses a Bearer-protected request answers with
    `WWW-Authenticate`, and the challenge is where a client learns where to
    get a token — it is how the Microsoft identity libraries discover the
    authority. All four OAuth mounts answered 401 with a body and no
    challenge, so a client written against mockdr would be written without
    the step the real service requires.
    """

    MOUNTS = [
        ("/cs/devices/queries/devices/v1", "/cs/oauth2/token"),
        ("/mde/api/machines", "/mde/oauth2/v2.0/token"),
        ("/graph/v1.0/users", "/graph/oauth2/v2.0/token"),
    ]

    @pytest.mark.parametrize(("path", "token_path"), MOUNTS)
    def test_a_request_with_no_token_is_told_where_to_get_one(
        self, client: TestClient, path: str, token_path: str,
    ) -> None:
        challenge = client.get(path).headers.get("www-authenticate", "")
        assert challenge.startswith("Bearer ")
        assert f'authorization_uri="http://testserver{token_path}"' in challenge

    @pytest.mark.parametrize(("path", "token_path"), MOUNTS)
    def test_nothing_was_wrong_with_a_token_never_sent(
        self, client: TestClient, path: str, token_path: str,
    ) -> None:
        """§3.1: an error code belongs only on a token that was sent."""
        assert "error=" not in client.get(path).headers.get("www-authenticate", "")

    @pytest.mark.parametrize(("path", "token_path"), MOUNTS)
    def test_a_token_that_was_refused_says_so(
        self, client: TestClient, path: str, token_path: str,
    ) -> None:
        challenge = client.get(
            path, headers={"Authorization": "Bearer zzz-no-such-token"},
        ).headers.get("www-authenticate", "")
        assert 'error="invalid_token"' in challenge
        assert "error_description=" in challenge

    def test_the_body_still_says_what_it_said(self, client: TestClient) -> None:
        """The challenge is additional; a client reading the body is
        unaffected."""
        body = client.get("/graph/v1.0/users").json()
        assert body["error"]["code"] == "InvalidAuthenticationToken"


class TestATokenAnswerIsNeverCached:
    """RFC 6749 §5.1, which every OAuth mount here ignored.

    The authorization server must answer a token request with
    `Cache-Control: no-store`, and the section adds `Pragma: no-cache` for
    the caches that predate it. A proxy or a client library following its own
    cache rules could otherwise keep a bearer token and hand it out again —
    which is the reason the requirement exists, and a client built against
    mockdr would not have been designed around it.
    """

    TOKENS = [
        ("/cs/oauth2/token", {
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
            "grant_type": "client_credentials"}),
        ("/mde/oauth2/v2.0/token", {
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials"}),
        ("/graph/oauth2/v2.0/token", {
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials"}),
        ("/sentinel/oauth2/v2.0/token", {
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials"}),
    ]

    @pytest.mark.parametrize(("path", "form"), TOKENS)
    def test_the_answer_says_do_not_store_it(
        self, client: TestClient, path: str, form: dict,
    ) -> None:
        response = client.post(path, data=form)
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"

    def test_a_protected_route_is_left_alone(self, client: TestClient) -> None:
        """Only the endpoints that mint tokens are touched."""
        assert "cache-control" not in client.get("/graph/v1.0/users").headers


class TestOneDirectoryAnswersOneWay:
    """Three mounts sit behind the same Entra directory in this mock.

    Defender and Graph refused a grant they do not issue for; Sentinel took
    `grant_type` as a form field and never looked at it, so it minted a token
    for `grant_type=password` — and for a request that named no grant at all.
    One identity platform cannot answer three ways.
    """

    SENTINEL = "/sentinel/oauth2/v2.0/token"
    CREDENTIALS = {"client_id": "sentinel-mock-client-id",
                   "client_secret": "sentinel-mock-client-secret",
                   # Entra requires the scope on this grant.
                   "scope": "https://management.azure.com/.default"}

    def test_a_grant_it_does_not_issue_for(self, client: TestClient) -> None:
        response = client.post(self.SENTINEL,
                               data={**self.CREDENTIALS, "grant_type": "password"})
        assert response.status_code == 400
        assert response.json()["error"] == "unsupported_grant_type"
        assert response.json()["error_codes"] == [70003]

    def test_a_request_that_names_no_grant(self, client: TestClient) -> None:
        response = client.post(self.SENTINEL, data=self.CREDENTIALS)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert "'grant_type'" in response.json()["error_description"]

    def test_the_grant_it_does_issue_for_still_works(
        self, client: TestClient,
    ) -> None:
        response = client.post(
            self.SENTINEL,
            data={**self.CREDENTIALS, "grant_type": "client_credentials"})
        assert response.status_code == 200
        assert response.json()["token_type"] == "Bearer"

    def test_the_token_body_is_the_v2_one(self, client: TestClient) -> None:
        """`resource` belongs to the v1.0 endpoint this mount is not, and the
        two other Entra mounts here have never sent it."""
        bodies = []
        for path, credentials in (
            ("/mde/oauth2/v2.0/token",
             {"client_id": "mde-mock-admin-client",
              "client_secret": "mde-mock-admin-secret",
              "scope": "https://api.securitycenter.microsoft.com/.default"}),
            ("/graph/oauth2/v2.0/token",
             {"client_id": "graph-mock-admin-client",
              "client_secret": "graph-mock-admin-secret",
              "scope": "https://graph.microsoft.com/.default"}),
            (self.SENTINEL, self.CREDENTIALS),
        ):
            bodies.append(client.post(path, data={
                **credentials, "grant_type": "client_credentials"}).json())
        assert {frozenset(b) for b in bodies} == {frozenset(
            {"access_token", "token_type", "expires_in", "ext_expires_in"})}

    def test_the_three_entra_mounts_refuse_alike(
        self, client: TestClient,
    ) -> None:
        errors = set()
        for path, credentials in (
            ("/mde/oauth2/v2.0/token",
             {"client_id": "mde-mock-admin-client",
              "client_secret": "mde-mock-admin-secret",
              "scope": "https://api.securitycenter.microsoft.com/.default"}),
            ("/graph/oauth2/v2.0/token",
             {"client_id": "graph-mock-admin-client",
              "client_secret": "graph-mock-admin-secret",
              "scope": "https://graph.microsoft.com/.default"}),
            (self.SENTINEL, self.CREDENTIALS),
        ):
            body = client.post(
                path, data={**credentials, "grant_type": "password"}).json()
            errors.add((body["error"], tuple(body["error_codes"])))
        assert len(errors) == 1


class TestSplunkWritesJsonTheWaySplunkdWrites:
    """Measured on 10.4.2 by creating a saved search whose name is not ASCII.

    splunkd writes its JSON compact — `{"name":"x"}`, no space after the
    colon — and writes non-ASCII as the UTF-8 bytes themselves. mockdr's
    Splunk mount did neither consistently: the paging, search, sort and
    field-filter middlewares each re-serialised with Python's defaults, so
    the same collection came back escaped and spaced through one parameter
    and compact through another. The same value to a parser, a different one
    to anything that reads the bytes — which is what a SIEM ingesting a raw
    response does, and what the conformance harness, comparing parsed
    documents, could never see.
    """

    SPLUNK = {"Authorization": "Basic " + base64.b64encode(
        b"admin:mockdr-admin").decode()}
    NAME = "zzz-Grüße-日本語"

    def _create(self, client: TestClient) -> None:
        client.post("/splunk/services/saved/searches", headers=self.SPLUNK,
                    data={"name": self.NAME, "search": "index=main"})

    @pytest.mark.parametrize("params", [
        {"output_mode": "json", "count": "0"},
        {"output_mode": "json", "count": "0", "search": "zzz"},
        {"output_mode": "json", "count": "0", "sort_key": "name"},
        {"output_mode": "json", "count": "0", "f": "search"},
    ])
    def test_the_bytes_are_utf8_and_compact(
        self, client: TestClient, params: dict,
    ) -> None:
        self._create(client)
        raw = client.get("/splunk/services/saved/searches",
                         headers=self.SPLUNK, params=params).content

        assert "日本語".encode() in raw
        assert rb"\u65e5" not in raw
        assert b'": "' not in raw

    def test_one_server_renders_one_way(self, client: TestClient) -> None:
        """It rendered the same collection two ways depending on which
        parameter the client happened to send."""
        self._create(client)
        spacings = set()
        for params in ({"output_mode": "json", "count": "0"},
                       {"output_mode": "json", "count": "0", "search": "zzz"},
                       {"output_mode": "json", "count": "0", "sort_key": "name"}):
            raw = client.get("/splunk/services/saved/searches",
                             headers=self.SPLUNK, params=params).content
            spacings.add(b'": "' in raw)
        assert spacings == {False}

    def test_a_refusal_is_rendered_the_same_way(
        self, client: TestClient,
    ) -> None:
        response = client.get("/splunk/services/data/indexes",
                              headers=self.SPLUNK,
                              params={"output_mode": "json", "count": "-2"})
        assert b'": "' not in response.content


class TestTheElasticProductsNameThemselves:
    """Measured on Elasticsearch 8.15 and Kibana 8.15.

    `X-elastic-product: Elasticsearch` is not decoration: every official
    Elasticsearch client since 7.14 — Python, JavaScript, Java, Go — reads it
    off the first response and refuses to talk to a server that does not send
    it, with an `UnsupportedProductError`. mockdr never sent it, so the one
    client this mount exists for could not use it at all.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}
    KBN = {**ES, "kbn-xsrf": "true"}

    @pytest.mark.parametrize("path", [
        "/elastic/",
        "/elastic/_cluster/health",
        "/elastic/zzz-no-such-index/_search",
        "/elastic/_cat/indices",
    ])
    def test_every_answer_names_the_product(
        self, client: TestClient, path: str,
    ) -> None:
        response = client.get(path, headers=self.ES)
        assert response.headers["x-elastic-product"] == "Elasticsearch"

    def test_the_401_that_asks_for_credentials_does_not(
        self, client: TestClient,
    ) -> None:
        """The header goes on once the request has been authenticated."""
        response = client.get("/elastic/_cluster/health")
        assert response.status_code == 401
        assert "x-elastic-product" not in response.headers

    def test_another_product_is_not_elasticsearch(
        self, client: TestClient,
    ) -> None:
        assert "x-elastic-product" not in client.get(
            "/splunk/services/data/indexes").headers

    @pytest.mark.parametrize("path", [
        "/kibana/api/status",
        "/kibana/api/zzz-no-such-route",
        "/kibana/api/cases/_find",
    ])
    def test_kibana_names_itself_on_every_answer(
        self, client: TestClient, path: str,
    ) -> None:
        response = client.get(path, headers=self.KBN)
        assert response.headers["kbn-name"]
        assert len(response.headers["kbn-license-sig"]) == 64
        assert response.headers["cache-control"] == (
            "private, no-cache, no-store, must-revalidate")

    def test_the_node_name_is_the_one_status_reports(
        self, client: TestClient,
    ) -> None:
        """A client reading both must not see two Kibanas."""
        status = client.get("/kibana/api/status", headers=self.KBN)
        assert status.headers["kbn-name"] == status.json()["name"]


class TestSplunkdNamesItselfAndItsCaching:
    """Measured on 10.4.2, header by header.

    `Server: uvicorn` is the plainest way there is to tell the two apart, and
    it was there on every answer. Under it: splunkd says what each answer
    depends on, says how it may be kept, and publishes a validator for the
    one family it serves as cacheable — `data/indexes` — which it then
    answers `304 Not Modified` for. mockdr said none of it, so a client
    revalidating a cached read was handed the whole collection every time.
    """

    SPLUNK = {"Authorization": "Basic " + base64.b64encode(
        b"admin:mockdr-admin").decode()}
    UNCACHEABLE = "no-store, no-cache, must-revalidate, max-age=0"

    def test_the_server_is_splunkd(self, client: TestClient) -> None:
        response = client.get("/splunk/services/server/info", headers=self.SPLUNK)
        assert response.headers["server"] == "Splunkd"

    def test_a_read_says_what_it_depends_on(self, client: TestClient) -> None:
        response = client.get("/splunk/services/saved/searches",
                              headers=self.SPLUNK)
        # The test client offers gzip, so the encoding joins what a
        # compressed answer varies on; who asked is the part that is always
        # there.
        named = {p.strip().lower() for p in response.headers["vary"].split(",")}
        assert {"cookie", "authorization"} <= named

    def test_a_session_token_is_refused_before_the_cookie(
        self, client: TestClient,
    ) -> None:
        """splunkd never reaches its cookie handler for one it cannot resolve."""
        response = client.get("/splunk/services/data/indexes",
                              headers={"Authorization": "Splunk zzz-not-a-key"})
        assert response.headers["vary"] == "Authorization"

    def test_the_collector_varies_on_the_credential_alone(
        self, client: TestClient,
    ) -> None:
        response = client.post("/splunk/services/collector/event",
                               headers={"Authorization": "Splunk zzz"},
                               json={"event": "x"})
        assert response.headers["vary"] == "Authorization"

    def test_a_token_in_the_query_never_reaches_the_header(
        self, client: TestClient,
    ) -> None:
        response = client.post("/splunk/services/collector/event",
                               params={"token": "zzz"}, json={"event": "x"})
        assert "vary" not in response.headers

    def test_almost_nothing_is_cacheable(self, client: TestClient) -> None:
        response = client.get("/splunk/services/saved/searches",
                              headers=self.SPLUNK)
        assert response.headers["cache-control"] == self.UNCACHEABLE
        assert response.headers["expires"] == "Thu, 26 Oct 1978 00:00:00 GMT"

    def test_the_index_family_is(self, client: TestClient) -> None:
        response = client.get("/splunk/services/data/indexes",
                              headers=self.SPLUNK,
                              params={"output_mode": "json"})
        assert response.headers["cache-control"] == (
            "must-revalidate, private, max-age=1800")
        assert response.headers["etag"].startswith('W/"')

    def test_only_when_the_read_succeeded(self, client: TestClient) -> None:
        """A 404 under the same family carries no validator."""
        response = client.get("/splunk/services/data/indexes/zzz-no-such",
                              headers=self.SPLUNK, params={"output_mode": "json"})
        assert response.status_code == 404
        assert response.headers["cache-control"] == self.UNCACHEABLE
        assert "etag" not in response.headers

    def test_a_fresh_read_is_answered_304(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The validator is over the body, and the feed's own `updated` is
        the time of the response — on splunkd too, measured: three reads in
        a row carry three different ETags there as well. So the two reads
        below are held inside one second, which is the window in which the
        product itself promises a match.
        """
        import time as clock

        from utils.splunk import response as splunk_response

        frozen = clock.gmtime()
        monkeypatch.setattr(splunk_response.time, "gmtime", lambda *a: frozen)

        first = client.get("/splunk/services/data/indexes", headers=self.SPLUNK,
                           params={"output_mode": "json"})
        again = client.get(
            "/splunk/services/data/indexes",
            headers={**self.SPLUNK, "If-None-Match": first.headers["etag"]},
            params={"output_mode": "json"})

        assert again.status_code == 304
        assert again.content == b""
        assert again.headers["etag"] == first.headers["etag"]

    def test_a_stale_validator_gets_the_collection(
        self, client: TestClient,
    ) -> None:
        response = client.get(
            "/splunk/services/data/indexes",
            headers={**self.SPLUNK, "If-None-Match": 'W/"zzz-not-the-etag"'},
            params={"output_mode": "json"})
        assert response.status_code == 200
        assert response.json()["entry"]

    def test_a_refused_credential_says_only_that_it_is_not_shared(
        self, client: TestClient,
    ) -> None:
        response = client.get("/splunk/services/data/indexes")
        assert response.status_code == 401
        assert response.headers["cache-control"] == "private"
        assert "expires" not in response.headers

    def test_a_mode_it_could_not_read_says_the_same(
        self, client: TestClient,
    ) -> None:
        """That refusal comes from the layer that would have chosen the
        renderer — the same layer that refuses a credential."""
        response = client.get("/splunk/services/data/indexes",
                              headers=self.SPLUNK,
                              params={"output_mode": "zzz-not-a-mode"})
        assert response.status_code == 400
        assert response.headers["cache-control"] == "private"


class TestEachProductCompressesItsOwnWay:
    """Measured on all three runnable products, which do not agree.

    mockdr compressed nothing, which a client sees in every byte on the
    wire. Elasticsearch compresses a 74-byte answer and publishes no `Vary`;
    Kibana leaves an 828-byte answer alone; splunkd leaves a 127-byte refusal
    alone and names the encoding in the `Vary` it already sends.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}
    GZIP = {"Accept-Encoding": "gzip"}

    def test_elasticsearch_compresses_and_says_nothing(
        self, client: TestClient,
    ) -> None:
        response = client.get("/elastic/_cluster/health",
                              headers={**self.ES, **self.GZIP})
        assert response.headers["content-encoding"] == "gzip"
        assert "vary" not in response.headers

    def test_kibana_compresses_and_says_so(self, client: TestClient) -> None:
        response = client.get("/kibana/api/cases/_find",
                              headers={**self.ES, **self.GZIP, "kbn-xsrf": "true"},
                              params={"perPage": 20})
        assert len(response.content) > 0
        assert response.headers["content-encoding"] == "gzip"
        assert "accept-encoding" in response.headers["vary"].lower()

    def test_kibana_leaves_a_small_answer_alone(
        self, client: TestClient,
    ) -> None:
        """Measured: an 828-byte answer is not compressed, a 1546-byte one is."""
        response = client.get("/kibana/api/zzz-no-such-route",
                              headers={**self.ES, **self.GZIP, "kbn-xsrf": "true"})
        assert "content-encoding" not in response.headers

    def test_a_client_that_does_not_ask_is_not_given(
        self, client: TestClient,
    ) -> None:
        response = client.get("/elastic/_cluster/health",
                              headers={**self.ES, "Accept-Encoding": "identity"})
        assert "content-encoding" not in response.headers

    def test_the_collector_never_compresses(self, client: TestClient) -> None:
        response = client.post(
            "/splunk/services/collector/event",
            headers={"Authorization": "Splunk zzz", **self.GZIP},
            json={"event": "x" * 4000})
        assert "content-encoding" not in response.headers

    def test_a_mount_with_no_measured_product_is_left_alone(
        self, client: TestClient,
    ) -> None:
        response = client.get("/web/api/v2.1/agents", headers={
            "Authorization": "ApiToken admin-token-0000-0000-000000000001",
            **self.GZIP})
        assert "content-encoding" not in response.headers


class TestTheThreeThingsElasticsearchLetsAClientDo:
    """Measured on 8.15. They are not per-route features — every endpoint
    takes them — and mockdr took all three as decoration.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def test_filter_path_keeps_only_what_it_names(
        self, client: TestClient,
    ) -> None:
        body = client.get("/elastic/_cluster/health", headers=self.ES,
                          params={"filter_path": "status,cluster_name"}).json()
        assert set(body) == {"status", "cluster_name"}

    def test_a_leading_minus_drops_instead(self, client: TestClient) -> None:
        body = client.get("/elastic/_count", headers=self.ES,
                          params={"filter_path": "-_shards"}).json()
        assert "_shards" not in body
        assert "count" in body

    def test_a_dotted_path_reaches_inside(self, client: TestClient) -> None:
        body = client.post("/elastic/_search", headers=self.ES,
                           params={"filter_path": "hits.total,hits.hits._id",
                                   "size": "1"},
                           json={}).json()
        assert set(body) == {"hits"}
        assert set(body["hits"]) == {"total", "hits"}
        assert set(body["hits"]["hits"][0]) == {"_id"}

    def test_nothing_matching_is_an_empty_document(
        self, client: TestClient,
    ) -> None:
        """Not the whole one."""
        response = client.get("/elastic/_count", headers=self.ES,
                              params={"filter_path": "zzz-nothing"})
        assert response.json() == {}

    def test_a_wildcard_matches_one_segment(self, client: TestClient) -> None:
        body = client.get("/elastic/_count", headers=self.ES,
                          params={"filter_path": "_shards.*"}).json()
        assert set(body) == {"_shards"}
        assert "total" in body["_shards"]

    def test_pretty_prints_the_way_jackson_prints(
        self, client: TestClient,
    ) -> None:
        text = client.get("/elastic/_count", headers=self.ES,
                          params={"pretty": "", "filter_path": "count"}).text
        assert text.startswith('{\n  "count" : ')
        assert text.endswith("}\n")

    def test_pretty_false_is_not_pretty(self, client: TestClient) -> None:
        text = client.get("/elastic/_count", headers=self.ES,
                          params={"pretty": "false"}).text
        assert "\n" not in text

    def test_the_opaque_id_comes_back(self, client: TestClient) -> None:
        """The official clients offer it as `opaque_id`, to find a request
        again in a log."""
        response = client.get("/elastic/_count", headers={
            **self.ES, "X-Opaque-Id": "zzz-probe"})
        assert response.headers["x-opaque-id"] == "zzz-probe"

    def test_a_cat_answer_is_left_alone(self, client: TestClient) -> None:
        """`_cat` answers text, which none of this shapes."""
        response = client.get("/elastic/_cat/indices", headers=self.ES,
                              params={"pretty": ""})
        assert response.headers["content-type"].startswith("text/plain")
        assert "green open" in response.text

    def test_another_mount_is_not_shaped(self, client: TestClient) -> None:
        body = client.get("/kibana/api/status", headers={
            **self.ES, "kbn-xsrf": "true"},
            params={"filter_path": "name"}).json()
        assert set(body) != {"name"}


class TestCatSizesInTheUnitAsked:
    """Measured on 8.15.

    `_cat` takes a `bytes` parameter that chooses the unit, and mockdr's rows
    carried a rendered `180kb` — a string, which can only ever answer in one
    unit. A script reading `bytes=b` to sum sizes got text it could not add
    up.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def _size(self, client: TestClient, **params: str) -> str:
        rows = client.get("/elastic/_cat/indices", headers=self.ES, params={
            "format": "json", "h": "index,store.size", **params}).json()
        return str(rows[0]["store.size"])

    def test_without_a_unit_it_is_the_human_form(
        self, client: TestClient,
    ) -> None:
        assert self._size(client).endswith(("b", "kb", "mb", "gb"))

    def test_bytes_b_is_a_number(self, client: TestClient) -> None:
        assert self._size(client, bytes="b").isdigit()

    def test_a_unit_divides_and_truncates(self, client: TestClient) -> None:
        raw = int(self._size(client, bytes="b"))
        assert int(self._size(client, bytes="kb")) == raw // 1024
        assert int(self._size(client, bytes="mb")) == raw // 1024**2

    @pytest.mark.parametrize(("count", "expected"), [
        (249, "249b"), (1024, "1kb"), (1536, "1.5kb"),
        (79515, "77.6kb"), (184320, "180kb"), (1024**3, "1gb"),
    ])
    def test_the_human_form_is_the_products_own(
        self, count: int, expected: str,
    ) -> None:
        """One decimal at most, truncated rather than rounded, and none at
        all when it would be a zero."""
        from api.routers.es_search import _bytes_as

        assert _bytes_as(count, "") == expected

    def test_the_text_table_uses_the_unit_too(self, client: TestClient) -> None:
        text = client.get("/elastic/_cat/indices", headers=self.ES,
                          params={"h": "store.size", "bytes": "b"}).text
        assert all(line.strip().isdigit() for line in text.splitlines() if line.strip())


class TestWhatShapingDoesNotApplyTo:
    """Measured on 8.15: `_cat` answers a text table, which neither `pretty`
    nor `filter_path` shapes — unless `format=json` turns the answer into a
    document first. And a list that filters to nothing is written as nothing
    at all, where an object that filters to nothing is written `{}`.
    """

    ES = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode()}

    def test_pretty_does_not_touch_a_table(self, client: TestClient) -> None:
        plain = client.get("/elastic/_cat/health", headers=self.ES).text
        asked = client.get("/elastic/_cat/health", headers=self.ES,
                           params={"pretty": ""}).text
        assert asked == plain

    def test_filter_path_does_not_touch_a_table(
        self, client: TestClient,
    ) -> None:
        plain = client.get("/elastic/_cat/health", headers=self.ES).text
        asked = client.get("/elastic/_cat/health", headers=self.ES,
                           params={"filter_path": "zzz-nothing"}).text
        assert asked == plain

    def test_both_apply_once_the_answer_is_a_document(
        self, client: TestClient,
    ) -> None:
        text = client.get("/elastic/_cat/health", headers=self.ES,
                          params={"format": "json", "pretty": ""}).text
        assert text.startswith('[\n  {\n    "epoch" : ')

    def test_a_list_that_filters_to_nothing_is_nothing(
        self, client: TestClient,
    ) -> None:
        response = client.get("/elastic/_cat/health", headers=self.ES,
                              params={"format": "json",
                                      "filter_path": "zzz-nothing"})
        assert response.content == b""

    def test_an_object_that_filters_to_nothing_is_an_empty_one(
        self, client: TestClient,
    ) -> None:
        response = client.get("/elastic/_count", headers=self.ES,
                              params={"filter_path": "zzz-nothing"})
        assert response.content == b"{}"


class TestEntraWantsToKnowWhatTheTokenIsFor:
    """`scope` is required on the client-credentials grant at the v2 endpoint.

    All three Entra mounts took it as a form field and never looked at it —
    Graph's own docstring said so — and issued a token for a request Entra
    would have refused. Every client written against mockdr could therefore
    omit the one parameter the real directory insists on, and fifteen of this
    repo's own test files did.
    """

    MOUNTS = [
        ("/graph/oauth2/v2.0/token", "graph-mock-admin-client",
         "graph-mock-admin-secret", "https://graph.microsoft.com/.default"),
        ("/mde/oauth2/v2.0/token", "mde-mock-admin-client",
         "mde-mock-admin-secret",
         "https://api.securitycenter.microsoft.com/.default"),
        ("/sentinel/oauth2/v2.0/token", "sentinel-mock-client-id",
         "sentinel-mock-client-secret", "https://management.azure.com/.default"),
    ]

    @pytest.mark.parametrize(("path", "client_id", "secret", "scope"), MOUNTS)
    def test_a_request_without_one_is_refused(
        self, client: TestClient, path: str, client_id: str, secret: str,
        scope: str,
    ) -> None:
        response = client.post(path, data={
            "client_id": client_id, "client_secret": secret,
            "grant_type": "client_credentials"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert "'scope'" in response.json()["error_description"]

    @pytest.mark.parametrize(("path", "client_id", "secret", "scope"), MOUNTS)
    def test_a_request_with_one_is_answered(
        self, client: TestClient, path: str, client_id: str, secret: str,
        scope: str,
    ) -> None:
        response = client.post(path, data={
            "client_id": client_id, "client_secret": secret,
            "grant_type": "client_credentials", "scope": scope})
        assert response.status_code == 200
        assert response.json()["token_type"] == "Bearer"

    def test_the_tenant_scoped_url_wants_it_too(
        self, client: TestClient,
    ) -> None:
        tenant = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        without = client.post(f"/graph/{tenant}/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials"})
        assert without.status_code == 400


class TestACortexBodyThatSaysWhichRecords:
    """Two routes were built to read a body and read none of it.

    `rbac/get_user_group` documents `group_names` and `quarantine/status`
    documents `files` — the reference lists no other member for either — and
    both were answered from a canned list. A client asking about one group
    got every group; a client asking whether *its* file was quarantined read
    somebody else's row and believed it was its own.
    """

    XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}

    def _groups(self, client: TestClient, request_data: dict) -> list[str]:
        reply = client.post("/xdr/public_api/v1/rbac/get_user_group/",
                            headers=self.XDR,
                            json={"request_data": request_data}).json()["reply"]
        return [g["group_name"] for g in reply]

    def test_a_body_that_names_a_group_gets_that_group(
        self, client: TestClient,
    ) -> None:
        assert self._groups(client, {"group_names": ["SOC Team"]}) == ["SOC Team"]

    def test_a_body_that_names_none_gets_all_of_them(
        self, client: TestClient,
    ) -> None:
        assert len(self._groups(client, {})) > 1

    def test_a_group_nobody_has(self, client: TestClient) -> None:
        assert self._groups(client, {"group_names": ["zzz-no-such"]}) == []

    def test_quarantine_answers_about_the_files_it_was_given(
        self, client: TestClient,
    ) -> None:
        reply = client.post("/xdr/public_api/v1/quarantine/status/",
                            headers=self.XDR,
                            json={"request_data": {"files": [
                                {"endpoint_id": "EP-9", "file_hash": "c" * 64,
                                 "file_path": "/opt/x"},
                            ]}}).json()["reply"]
        assert [r["endpoint_id"] for r in reply] == ["EP-9"]
        assert reply[0]["file_path"] == "/opt/x"

    def test_asking_about_no_files_answers_about_none(
        self, client: TestClient,
    ) -> None:
        reply = client.post("/xdr/public_api/v1/quarantine/status/",
                            headers=self.XDR,
                            json={"request_data": {}}).json()["reply"]
        assert reply == []


class TestARouteAnswersAboutWhatTheUrlNames:
    """A path parameter names the record the answer is meant to be about.

    Three routes ignored theirs. `/accounts/{id}/policy` answered the same
    document for every id — including ids the same install refuses on
    `/accounts/{id}` — and answered it as `{"data": null}`, a 200 with
    nothing in it, because the lookup underneath took a site or a group and
    there was no record for neither. `/endpoint/suggestions/{type}` answered
    the same list for a type Kibana has no such thing as.
    """

    S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}
    KBN = {"Authorization": "Basic " + base64.b64encode(
        b"elastic:mock-elastic-password").decode(), "kbn-xsrf": "true"}

    def _an_account(self, client: TestClient) -> str:
        return str(client.get("/web/api/v2.1/accounts", headers=self.S1,
                              params={"limit": 1}).json()["data"][0]["id"])

    def test_the_account_policy_is_a_document(self, client: TestClient) -> None:
        body = client.get(
            f"/web/api/v2.1/accounts/{self._an_account(client)}/policy",
            headers=self.S1).json()
        assert body["data"], "an account policy is not null"
        assert "mitigationMode" in body["data"]

    def test_the_tenant_policy_is_the_same_document(
        self, client: TestClient,
    ) -> None:
        tenant = client.get("/web/api/v2.1/tenant/policy",
                            headers=self.S1).json()["data"]
        site_id = client.get("/web/api/v2.1/sites", headers=self.S1
                             ).json()["data"]["sites"][0]["id"]
        site = client.get(f"/web/api/v2.1/sites/{site_id}/policy",
                          headers=self.S1).json()["data"]
        assert tenant
        assert set(tenant) == set(site)

    def test_an_account_this_install_does_not_have(
        self, client: TestClient,
    ) -> None:
        response = client.get("/web/api/v2.1/accounts/zzz-no-such/policy",
                              headers=self.S1)
        assert response.status_code == 404
        assert client.get("/web/api/v2.1/accounts/zzz-no-such",
                          headers=self.S1).status_code == 404

    def test_the_only_suggestion_type_kibana_has(
        self, client: TestClient,
    ) -> None:
        ok = client.post("/kibana/api/endpoint/suggestions/eventFilters",
                         headers=self.KBN,
                         json={"field": "host.os.name", "query": ""})
        assert ok.status_code == 200

    @pytest.mark.parametrize("suggestion_type", [
        "trustedApps", "endpointExceptions", "zzz-not-a-type",
    ])
    def test_every_other_type_is_refused(
        self, client: TestClient, suggestion_type: str,
    ) -> None:
        """Measured on 8.15, which refuses even Kibana's own `trustedApps`."""
        response = client.post(
            f"/kibana/api/endpoint/suggestions/{suggestion_type}",
            headers=self.KBN, json={"field": "host.os.name", "query": ""})
        assert response.status_code == 400
        assert response.json()["message"] == (
            "[request params.suggestion_type]: expected value to equal "
            "[eventFilters]")

    def test_the_suggestion_body_needs_a_query_too(
        self, client: TestClient,
    ) -> None:
        response = client.post("/kibana/api/endpoint/suggestions/eventFilters",
                               headers=self.KBN, json={"field": "host.os.name"})
        assert response.status_code == 400
        assert response.json()["message"] == (
            "[request body.query]: expected value of type [string] "
            "but got [undefined]")


class TestControllingASearchJob:
    """Measured on 10.4.2, action by action.

    Every control action answered the same generic line — `Action 'x'
    applied to job '<sid>'` — so a client reading the message could not tell
    a pause from a finalize, and the two that change the job's lifetime said
    nothing about it. Worse, `cancel` marked the job failed and *kept* it:
    splunkd removes it, so a client waiting for the sid to stop resolving
    waited for ever.
    """

    SPLUNK = {"Authorization": "Basic " + base64.b64encode(
        b"admin:mockdr-admin").decode()}

    def _job(self, client: TestClient) -> str:
        return str(client.post("/splunk/services/search/jobs",
                               headers=self.SPLUNK,
                               data={"search": "search index=main",
                                     "output_mode": "json"}).json()["sid"])

    def _control(self, client: TestClient, sid: str, action: str, **extra: str):
        return client.post(f"/splunk/services/search/jobs/{sid}/control",
                           headers=self.SPLUNK,
                           data={"action": action, "output_mode": "json", **extra})

    @pytest.mark.parametrize(("action", "said"), [
        ("pause", "Search job paused."),
        ("unpause", "Search job continued."),
        ("finalize", "Search job finalized."),
        ("touch", "Search job touched."),
        ("enablepreview", "Search job results preview enabled."),
        ("disablepreview", "Search job results preview disabled."),
    ])
    def test_each_action_says_what_it_did(
        self, client: TestClient, action: str, said: str,
    ) -> None:
        response = self._control(client, self._job(client), action)
        assert response.json()["messages"] == [{"type": "INFO", "text": said}]

    def test_saving_a_job_names_the_week_it_keeps_it_for(
        self, client: TestClient,
    ) -> None:
        sid = self._job(client)
        response = self._control(client, sid, "save")
        assert response.json()["messages"][0]["text"] == (
            "The ttl of the search job was changed to 604800.")

    def test_setting_a_ttl_names_it_and_sets_it(
        self, client: TestClient,
    ) -> None:
        sid = self._job(client)
        response = self._control(client, sid, "setttl", ttl="120")
        assert response.json()["messages"][0]["text"] == (
            "The ttl of the search job was changed to 120.")
        content = client.get(f"/splunk/services/search/jobs/{sid}",
                             headers=self.SPLUNK,
                             params={"output_mode": "json"},
                             ).json()["entry"][0]["content"]
        assert content["ttl"] == 120

    def test_a_cancelled_job_stops_resolving(self, client: TestClient) -> None:
        sid = self._job(client)
        assert self._control(client, sid, "cancel").json()["messages"] == [
            {"type": "INFO", "text": "Search job cancelled."}]
        assert client.get(f"/splunk/services/search/jobs/{sid}",
                          headers=self.SPLUNK,
                          params={"output_mode": "json"}).status_code == 404

    def test_an_action_splunkd_does_not_have(self, client: TestClient) -> None:
        """It names neither the action nor the job."""
        response = self._control(client, self._job(client), "zzz-not-an-action")
        assert response.status_code == 400
        assert response.json()["messages"] == [
            {"type": "FATAL", "text": "Unknown action."}]


class TestTheConnectorsOwnQueryFindsSomething:
    """This workspace's data connectors publish four custom tables — and the
    query a client runs against each of them.

    `dataConnectors` hands out `SentinelOne_CL | summarize max(TimeGenerated)`
    as the way to ask when data last arrived, and every one of the four
    tables answered an empty result with no columns at all. A client that
    read the connector list and ran the query it was given learned that a
    connector this workspace says is ingesting had ingested nothing. The
    events were there the whole time: the same install's Splunk store holds
    them, from the same four products.
    """

    def _headers(self, client: TestClient) -> dict:
        token = client.post("/sentinel/oauth2/v2.0/token", data={
            "client_id": "sentinel-mock-client-id",
            "client_secret": "sentinel-mock-client-secret",
            "grant_type": "client_credentials",
            "scope": "https://management.azure.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _query(self, client: TestClient, kql: str) -> dict:
        return dict(client.post("/sentinel/v1/workspaces/mockdr-workspace/query",
                                headers=self._headers(client),
                                json={"query": kql}).json()["tables"][0])

    def _connector_tables(self, client: TestClient) -> list[str]:
        base = ("/sentinel/subscriptions/s/resourceGroups/g/providers"
                "/Microsoft.OperationalInsights/workspaces/w/providers"
                "/Microsoft.SecurityInsights/dataConnectors")
        listing = client.get(base, headers=self._headers(client),
                             params={"api-version": "2024-03-01"}).json()
        return [
            data["name"]
            for connector in listing["value"]
            for data in (connector["properties"]
                         .get("connectorUiConfig", {})
                         .get("dataTypes") or [])
        ]

    def test_every_table_a_connector_advertises_has_data(
        self, client: TestClient,
    ) -> None:
        tables = self._connector_tables(client)
        assert tables, "the connectors advertise custom tables"
        for table in tables:
            answer = self._query(client, f"{table} | take 3")
            assert answer["rows"], f"{table} is empty"

    def test_the_query_the_connector_hands_out(
        self, client: TestClient,
    ) -> None:
        answer = self._query(
            client, "SentinelOne_CL | summarize max(TimeGenerated)")
        assert [c["name"] for c in answer["columns"]] == ["max_TimeGenerated"]
        assert answer["rows"][0][0]

    def test_a_row_carries_the_time_a_workspace_orders_by(
        self, client: TestClient,
    ) -> None:
        answer = self._query(client, "CrowdStrikeFalcon_CL | take 1")
        names = [c["name"] for c in answer["columns"]]
        assert "TimeGenerated" in names
        assert "SourceSystem" in names

    def test_each_table_holds_its_own_product(
        self, client: TestClient,
    ) -> None:
        """Not one pool of everything: a connector ingests what it connects."""
        s1 = self._query(client, "SentinelOne_CL | take 5")
        column = [c["name"] for c in s1["columns"]].index("SourceSystem")
        assert all(str(row[column]).startswith("sentinelone:") for row in s1["rows"])


class TestGraphHuntsTheSameDataDefenderDoes:
    """Graph's advanced hunting *is* Defender's, and this mount had the
    implementation Defender's own route was given up.

    The query was accepted and never evaluated: three synthetic rows came
    back whatever was asked, so a `where` that excludes everything returned
    results and a table this install does not have returned results too. The
    device ids in those rows belonged to no machine here, so a hunter who
    followed one got a 404 for a device the hunt had just reported.
    """

    def _headers(self, client: TestClient, mount: str) -> dict:
        clients = {
            "graph": ("graph-mock-admin-client", "graph-mock-admin-secret",
                      "https://graph.microsoft.com/.default"),
            "mde": ("mde-mock-admin-client", "mde-mock-admin-secret",
                    "https://api.securitycenter.microsoft.com/.default"),
        }
        client_id, secret, scope = clients[mount]
        token = client.post(f"/{mount}/oauth2/v2.0/token", data={
            "client_id": client_id, "client_secret": secret,
            "grant_type": "client_credentials", "scope": scope,
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _hunt(self, client: TestClient, mount: str, kql: str):
        path = ("/graph/v1.0/security/runHuntingQuery" if mount == "graph"
                else "/mde/api/advancedqueries/run")
        return client.post(path, headers=self._headers(client, mount),
                           json={"Query": kql})

    @pytest.mark.parametrize("kql", [
        "DeviceInfo | take 2",
        "AlertInfo | where Severity == 'High' | take 3",
        "AlertInfo | where Severity == 'zzz-nothing' | take 3",
    ])
    def test_both_mounts_answer_the_same_query_alike(
        self, client: TestClient, kql: str,
    ) -> None:
        graph = self._hunt(client, "graph", kql)
        mde = self._hunt(client, "mde", kql)
        assert graph.status_code == mde.status_code == 200
        assert len(graph.json()["Results"]) == len(mde.json()["Results"])

    def test_a_where_that_excludes_everything_returns_nothing(
        self, client: TestClient,
    ) -> None:
        """It used to return three rows."""
        body = self._hunt(
            client, "graph", "AlertInfo | where Severity == 'zzz-nothing'").json()
        assert body["Results"] == []
        assert body["Schema"], "a filtered-out query still has a schema"

    def test_a_table_this_install_does_not_have(
        self, client: TestClient,
    ) -> None:
        response = self._hunt(client, "graph", "ZzzNoSuchTable | take 1")
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "badRequest"

    def test_a_hunted_device_is_one_this_install_has(
        self, client: TestClient,
    ) -> None:
        """The canned rows named devices no machine here matched."""
        row = self._hunt(client, "graph", "DeviceInfo | take 1").json()["Results"][0]
        machine = client.get(f"/mde/api/machines/{row['DeviceId']}",
                             headers=self._headers(client, "mde"))
        assert machine.status_code == 200
        assert machine.json()["id"] == row["DeviceId"]


class TestAnAssigneeIsSomebodyTheTenantHas:
    """Cortex incidents were assigned to people the tenant had never heard of.

    `rbac/get_users` answered three canned role accounts while every incident
    drew a fresh invented name for its assignee — so a client that read an
    incident's `assigned_user_mail` and looked the person up in the tenant's
    own directory found nobody, every time, and could not tell whether the
    incident was assigned to a colleague or to nothing.
    """

    XDR = {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}

    def _users(self, client: TestClient) -> list[dict]:
        return list(client.post("/xdr/public_api/v1/rbac/get_users/",
                                headers=self.XDR,
                                json={"request_data": {}}).json()["reply"])

    def _incidents(self, client: TestClient) -> list[dict]:
        reply = client.post("/xdr/public_api/v1/incidents/get_incidents/",
                            headers=self.XDR,
                            json={"request_data": {}}).json()["reply"]
        return list(reply["incidents"] if isinstance(reply, dict) else reply)

    def test_every_assignee_is_in_the_directory(
        self, client: TestClient,
    ) -> None:
        directory = {u["user_email"] for u in self._users(client)}
        assigned = {
            i["assigned_user_mail"] for i in self._incidents(client)
            if i.get("assigned_user_mail")
        }
        assert assigned, "some incidents are assigned"
        assert assigned <= directory

    def test_the_directory_is_more_than_the_role_accounts(
        self, client: TestClient,
    ) -> None:
        """A tenant that assigns work has people to assign it to."""
        assert len(self._users(client)) > 3

    def test_an_assignee_carries_the_name_the_directory_gives(
        self, client: TestClient,
    ) -> None:
        by_mail = {u["user_email"]: u["pretty_name"] for u in self._users(client)}
        for incident in self._incidents(client):
            mail = incident.get("assigned_user_mail")
            if mail:
                assert incident["assigned_user_pretty_name"] == by_mail[mail]

    def test_the_role_accounts_are_still_there(
        self, client: TestClient,
    ) -> None:
        mails = {u["user_email"] for u in self._users(client)}
        assert {"admin@acmecorp.internal", "analyst@acmecorp.internal",
                "viewer@acmecorp.internal"} <= mails


class TestAnAlertNamesRecordsTheInstallHas:
    """The ids a Defender alert reports have to resolve where it says.

    A sweep over the seeded store for id-shaped fields that resolve nowhere
    found two on every Defender alert: `investigationId` was a
    `random.randint(1, 50)` and `incidentId` a `random.randint(1, 100)`, so
    an alert named an investigation `/api/investigations/{id}` answered 404
    for, and an incident neither Defender nor Graph had. This is the same
    failure as an incident assigned to somebody the tenant never employed:
    each single answer is plausible and the second request is the one that
    fails.
    """

    @staticmethod
    def _mde(client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _graph(client: TestClient) -> dict:
        token = client.post("/graph/oauth2/v2.0/token", data={
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://graph.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_every_investigation_an_alert_names_answers(
        self, client: TestClient,
    ) -> None:
        headers = self._mde(client)
        alerts = client.get("/mde/api/alerts", headers=headers).json()["value"]
        named = [a for a in alerts if a["investigationId"]]
        assert named, "no alert triggered an investigation"
        for alert in named:
            resp = client.get(
                f"/mde/api/investigations/{alert['investigationId']}", headers=headers,
            )
            assert resp.status_code == 200, alert["investigationId"]
            investigation = resp.json()
            # The investigation an alert set off is about that alert, on that
            # alert's machine, and in the state the alert reports.
            assert investigation["triggeringAlertId"] == alert["id"]
            assert investigation["machineId"] == alert["machineId"]
            assert investigation["state"] == alert["investigationState"]

    def test_every_incident_an_alert_names_answers(self, client: TestClient) -> None:
        mde, graph = self._mde(client), self._graph(client)
        alerts = client.get("/mde/api/alerts", headers=mde).json()["value"]
        for alert in alerts:
            resp = client.get(
                f"/graph/v1.0/security/incidents/{alert['incidentId']}", headers=graph,
            )
            assert resp.status_code == 200, alert["incidentId"]

    def test_the_two_surfaces_agree_on_which_incident(
        self, client: TestClient,
    ) -> None:
        """The same alert, read through Defender and through Graph."""
        mde, graph = self._mde(client), self._graph(client)
        alerts = {a["id"]: a for a in client.get("/mde/api/alerts", headers=mde).json()["value"]}
        graph_alerts = client.get(
            "/graph/v1.0/security/alerts_v2", headers=graph,
        ).json()["value"]
        compared = 0
        for graph_alert in graph_alerts:
            counterpart = alerts.get(graph_alert["providerAlertId"])
            if counterpart is None:
                continue
            compared += 1
            assert graph_alert["incidentId"] == str(counterpart["incidentId"])
        assert compared, "no Graph alert came from a Defender alert"


class TestFalconAssignsWorkToItsOwnUsers:
    """Detections, incidents and cases, assigned to people the tenant has.

    All three invented an assignee: a detection took `fake.email()` and an
    unrelated `fake.name()`, an incident took another pair, and a case was
    assigned by `analyst0@acmecorp.internal` to `responder0@acmecorp.internal`
    — addresses `/user-management/queries/users/v1` has never heard of. Same
    failure as the Cortex incidents assigned to nobody: the assignment reads
    fine until someone looks the person up.
    """

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client",
            "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _users(client: TestClient, headers: dict) -> list[dict]:
        ids = client.get(
            "/cs/user-management/queries/users/v1", headers=headers, params={"limit": 500},
        ).json()["resources"]
        return list(client.post(
            "/cs/user-management/entities/users/GET/v1", headers=headers, json={"ids": ids},
        ).json()["resources"])

    def test_a_detection_is_assigned_to_a_console_user(
        self, client: TestClient,
    ) -> None:
        headers = self._auth(client)
        users = self._users(client, headers)
        addresses = {u["uid"] for u in users}
        names = {f"{u['first_name']} {u['last_name']}" for u in users}

        ids = client.get(
            "/cs/alerts/queries/alerts/v2", headers=headers, params={"limit": 500},
        ).json()["resources"]
        detections = client.post(
            "/cs/alerts/entities/alerts/v2", headers=headers, json={"composite_ids": ids},
        ).json()["resources"]
        assigned = [d for d in detections if d.get("assigned_to_uid")]
        assert assigned, "no detection is assigned to anybody"
        for detection in assigned:
            assert detection["assigned_to_uid"] in addresses
            # The name belongs to that address, rather than to nobody.
            assert detection["assigned_to_name"] in names

    def test_a_case_is_assigned_between_console_users(
        self, client: TestClient,
    ) -> None:
        headers = self._auth(client)
        addresses = {u["uid"] for u in self._users(client, headers)}
        ids = client.get(
            "/cs/cases/queries/cases/v1", headers=headers, params={"limit": 500},
        ).json()["resources"]
        cases = client.post(
            "/cs/message-center/entities/cases/GET/v1", headers=headers, json={"ids": ids},
        ).json()["resources"]
        assert cases
        for case in cases:
            assert case["assigner"]["uid"] in addresses
            assert case["assigner"]["email_address"] in addresses
            # gofalcon's case entity carries `assigner` and no `assignee`.
            assert "assignee" not in case


class TestFalconGroupsAndTheFilterThatNamesThem:
    """FQL groups terms with parentheses, and Falcon's own form used them.

    `(device_id:['…'])` — what Falcon's documentation and its console write,
    and what a host-group action carries — was cut apart by hand into an id
    with `'])` still attached. It matched no host, so `add-hosts` answered
    `200` with an empty `resources` list and the host was not in the group.
    The mount's FQL parser did not know parentheses either: a lone group was
    refused, and a group beside another term was dropped in silence, so
    `(status:'normal')+platform_name:'Windows'` answered every Windows host
    instead of the normal ones — a wider set than the caller asked for.
    """

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _members(self, client: TestClient, cs: dict, group: str) -> list[str]:
        return list(client.get(
            "/cs/devices/queries/host-group-members/v1", headers=cs, params={"id": group},
        ).json()["resources"])

    def test_a_host_joins_the_group_the_filter_names(self, client: TestClient) -> None:
        cs = self._auth(client)
        device = client.get(
            "/cs/devices/queries/devices/v1", headers=cs, params={"limit": 1},
        ).json()["resources"][0]
        group = client.get(
            "/cs/devices/combined/host-groups/v1", headers=cs, params={"limit": 1},
        ).json()["resources"][0]["id"]

        answer = client.post(
            "/cs/devices/entities/host-group-actions/v1", headers=cs,
            params={"action_name": "add-hosts"},
            json={"ids": [group], "action_parameters": [
                {"name": "filter", "value": f"(device_id:['{device}'])"},
            ]},
        )
        assert answer.status_code == 200
        assert answer.json()["resources"] == [{"id": device}]
        assert device in self._members(client, cs, group)

        # And the device says so, which is where a client looks.
        entity = client.post(
            "/cs/devices/entities/devices/v2", headers=cs, json={"ids": [device]},
        ).json()["resources"][0]
        assert group in entity["groups"]

    def test_removing_takes_the_same_form(self, client: TestClient) -> None:
        cs = self._auth(client)
        device = client.get(
            "/cs/devices/queries/devices/v1", headers=cs, params={"limit": 1},
        ).json()["resources"][0]
        group = client.get(
            "/cs/devices/combined/host-groups/v1", headers=cs, params={"limit": 1},
        ).json()["resources"][0]["id"]
        filters = [{"name": "filter", "value": f"(device_id:['{device}'])"}]
        client.post("/cs/devices/entities/host-group-actions/v1", headers=cs,
                    params={"action_name": "add-hosts"},
                    json={"ids": [group], "action_parameters": filters})
        client.post("/cs/devices/entities/host-group-actions/v1", headers=cs,
                    params={"action_name": "remove-hosts"},
                    json={"ids": [group], "action_parameters": filters})
        assert device not in self._members(client, cs, group)

    def test_a_grouped_term_still_narrows_the_query(self, client: TestClient) -> None:
        cs = self._auth(client)

        def total(fql: str) -> int:
            return int(client.get(
                "/cs/devices/queries/devices/v1", headers=cs,
                params={"limit": 200, "filter": fql},
            ).json()["meta"]["pagination"]["total"])

        bare = total("status:'normal'+platform_name:'Windows'")
        grouped = total("(status:'normal')+platform_name:'Windows'")
        assert grouped == bare
        assert grouped < total("platform_name:'Windows'")

    def test_a_group_on_its_own_is_read_not_refused(self, client: TestClient) -> None:
        cs = self._auth(client)
        answer = client.get(
            "/cs/devices/queries/devices/v1", headers=cs,
            params={"limit": 200, "filter": "(platform_name:'Windows')"},
        )
        assert answer.status_code == 200
        plain = client.get(
            "/cs/devices/queries/devices/v1", headers=cs,
            params={"limit": 200, "filter": "platform_name:'Windows'"},
        ).json()["meta"]["pagination"]["total"]
        assert answer.json()["meta"]["pagination"]["total"] == plain


class TestAnEntryReportsWhenItChanged:
    """An entry's `updated` is the entity's, not the time of the read.

    Measured on splunkd 10.4.2: every entry's `updated` is stable across
    reads, and for an entity nothing has changed through the REST layer —
    `saved/searches`, `apps/local` — it is the epoch. mockdr answered *now*
    for every entry of every collection, so each read reported that
    everything had just been updated, and the body changed once a second
    while nothing in it did. The ETag over that body could never be
    revalidated by a client that waited.
    """

    SPLUNK_AUTH = {"Authorization": "Basic YWRtaW46bW9ja2RyLWFkbWlu"}
    COLLECTIONS = (
        "/splunk/services/data/indexes",
        "/splunk/services/saved/searches",
        "/splunk/services/authentication/users",
        "/splunk/services/apps/local",
    )

    def test_two_reads_report_the_same_entry_timestamp(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import time as clock

        from utils.splunk import response as splunk_response

        for path in self.COLLECTIONS:
            first = client.get(
                path, headers=self.SPLUNK_AUTH, params={"output_mode": "json"},
            ).json()["entry"][0]["updated"]
            # A second later, by the renderer's own clock.
            later = clock.gmtime(clock.mktime(clock.gmtime()) + 60)
            monkeypatch.setattr(splunk_response.time, "gmtime", lambda *a, _t=later: _t)
            second = client.get(
                path, headers=self.SPLUNK_AUTH, params={"output_mode": "json"},
            ).json()["entry"][0]["updated"]
            monkeypatch.undo()
            assert first == second, path

    def test_an_unchanged_entity_carries_the_epoch(self, client: TestClient) -> None:
        for path in self.COLLECTIONS:
            entry = client.get(
                path, headers=self.SPLUNK_AUTH, params={"output_mode": "json"},
            ).json()["entry"][0]
            assert entry["updated"] == "1970-01-01T00:00:00+00:00", path

    def test_the_feed_still_reports_the_time_of_the_read(
        self, client: TestClient,
    ) -> None:
        """splunkd's feed-level `updated` *is* the response time — it changes
        between two reads there too, which is why the validator over the body
        does as well."""
        body = client.get(
            self.COLLECTIONS[0], headers=self.SPLUNK_AUTH, params={"output_mode": "json"},
        ).json()
        assert body["updated"] != "1970-01-01T00:00:00+00:00"
