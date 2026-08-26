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
import re

import pytest
from fastapi.testclient import TestClient

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
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "scope": "https://api.securitycenter.microsoft.com/.default",
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
            "client_id": "graph-mock-admin-client",
            "client_secret": "graph-mock-admin-secret",
            "scope": "https://graph.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _mde(self, client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "grant_type": "client_credentials",
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "scope": "https://api.securitycenter.microsoft.com/.default",
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
