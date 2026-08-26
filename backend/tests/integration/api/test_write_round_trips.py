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
