"""Lookups, tstats, chart and append through the search job API.

What Splunk Enterprise Security's correlation searches are built from, run
the way a client runs them: dispatch a job, read its results. Each of these
was refused with "Unknown search command" before, as a 400 to the dispatch.

The tables a lookup reads are resolved through lookup definitions, which
``data/transforms/lookups`` lists and creates; the seeded ones cover the KV
Store collections (the ES threat-intel collections, the XSOAR user mapping)
and two CSV tables derived from the seeded fleet. ``tstats`` reads the CIM
data models ``datamodel/model`` lists, filled from the EDR bridge's events.
"""
from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient

from repository.store import store

AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
JOBS = "/splunk/services/search/jobs"
TRANSFORMS = "/splunk/servicesNS/nobody/search/data/transforms/lookups"
KV_CONFIG = "/splunk/servicesNS/nobody/search/storage/collections/config"
KV_DATA = "/splunk/servicesNS/nobody/search/storage/collections/data"


def oneshot(client: TestClient, search: str) -> dict:
    """A oneshot search's JSON body."""
    resp = client.post(JOBS, data={"search": search, "exec_mode": "oneshot",
                                   "output_mode": "json", "count": 0}, headers=AUTH)
    assert resp.status_code == 200, resp.text
    return resp.json()


def rows(client: TestClient, search: str) -> list[dict]:
    """The results of a search that must run."""
    body = oneshot(client, search)
    fatal = [m for m in body.get("messages", []) if m.get("type") == "FATAL"]
    assert not fatal, fatal
    return body["results"]


def job(client: TestClient, search: str) -> dict:
    """A dispatched job's content."""
    sid = client.post(JOBS, data={"search": search, "output_mode": "json"},
                      headers=AUTH).json()["sid"]
    return client.get(f"{JOBS}/{sid}", params={"output_mode": "json"},
                      headers=AUTH).json()["entry"][0]["content"]


class TestLookupDefinitions:
    """``data/transforms/lookups``: listed, read, created and removed."""

    def test_the_seeded_definitions_are_listed(self, client: TestClient) -> None:
        body = client.get(TRANSFORMS, params={"output_mode": "json"}, headers=AUTH).json()
        assert [e["name"] for e in body["entry"]] == [
            "file_intel", "incident_review_lookup", "ip_intel", "mockdr_assets",
            "mockdr_identities", "splunk_xsoar_users",
        ]

    def test_a_kvstore_definition_names_its_collection_and_app(
        self, client: TestClient,
    ) -> None:
        entry = client.get(f"{TRANSFORMS}/ip_intel", params={"output_mode": "json"},
                           headers=AUTH).json()["entry"][0]
        assert entry["acl"]["app"] == "SA-ThreatIntelligence"
        assert "/servicesNS/nobody/SA-ThreatIntelligence/" in entry["id"]
        content = entry["content"]
        assert (content["collection"], content["external_type"], content["type"]) == (
            "ip_intel", "kvstore", "kvstore")
        assert content["fields_list"].startswith("_key,")
        assert "external_cmd" not in content

    def test_a_file_definition_names_its_file(self, client: TestClient) -> None:
        content = client.get(f"{TRANSFORMS}/mockdr_assets", params={"output_mode": "json"},
                             headers=AUTH).json()["entry"][0]["content"]
        assert (content["filename"], content["type"]) == ("mockdr_assets.csv", "file")

    def test_one_it_does_not_have_is_404(self, client: TestClient) -> None:
        resp = client.get(f"{TRANSFORMS}/nosuch", params={"output_mode": "json"}, headers=AUTH)
        assert resp.status_code == 404
        assert resp.json()["messages"][0]["text"] == "Could not find object id=nosuch"

    def test_a_definition_needs_a_name(self, client: TestClient) -> None:
        resp = client.post(TRANSFORMS, data={"collection": "x", "output_mode": "json"},
                           headers=AUTH)
        assert resp.status_code == 400

    def test_and_a_table(self, client: TestClient) -> None:
        resp = client.post(TRANSFORMS, data={"name": "x", "output_mode": "json"}, headers=AUTH)
        assert resp.status_code == 400

    def test_a_name_already_defined_is_409(self, client: TestClient) -> None:
        resp = client.post(TRANSFORMS, data={"name": "ip_intel", "collection": "ip_intel",
                                             "output_mode": "json"}, headers=AUTH)
        assert resp.status_code == 409
        assert resp.json()["messages"][0]["text"] == "An object with name=ip_intel already exists"

    def test_removing_one_it_does_not_have_is_404(self, client: TestClient) -> None:
        resp = client.delete(f"{TRANSFORMS}/nosuch", params={"output_mode": "json"},
                             headers=AUTH)
        assert resp.status_code == 404


class TestALookupOfYourOwn:
    """Create a collection, fill it, define a lookup over it, search it."""

    def _define(self, client: TestClient) -> None:
        client.post(KV_CONFIG, data={"name": "owners", "output_mode": "json"}, headers=AUTH)
        for record in ({"_key": "1", "host": "srv-1", "owner": "alice"},
                       {"_key": "2", "host": "srv-2", "owner": "bob"}):
            client.post(f"{KV_DATA}/owners", content=json.dumps(record), headers={
                **AUTH, "Content-Type": "application/json"})
        resp = client.post(TRANSFORMS, data={
            "name": "owners_lookup", "external_type": "kvstore", "collection": "owners",
            "fields_list": "_key,host,owner", "output_mode": "json",
        }, headers=AUTH)
        assert resp.status_code == 201
        assert resp.json()["entry"][0]["name"] == "owners_lookup"

    def test_inputlookup_reads_the_collection(self, client: TestClient) -> None:
        self._define(client)
        assert rows(client, "| inputlookup owners_lookup") == [
            {"_key": "1", "host": "srv-1", "owner": "alice"},
            {"_key": "2", "host": "srv-2", "owner": "bob"},
        ]

    def test_lookup_enriches_with_it(self, client: TestClient) -> None:
        self._define(client)
        found = rows(client, '| makeresults | eval host="srv-2" '
                             "| lookup owners_lookup host OUTPUT owner | table host owner")
        assert found == [{"host": "srv-2", "owner": "bob"}]

    def test_a_removed_definition_is_gone_from_the_search_too(
        self, client: TestClient,
    ) -> None:
        self._define(client)
        assert client.delete(f"{TRANSFORMS}/owners_lookup", params={"output_mode": "json"},
                             headers=AUTH).status_code == 200
        body = oneshot(client, "| inputlookup owners_lookup")
        assert body["messages"][0]["text"] == (
            "Error in 'inputlookup' command: The lookup table 'owners_lookup' requires "
            "a .csv or KV store lookup definition."
        )

    def test_the_xsoar_user_mapping_reads_back(self, client: TestClient) -> None:
        client.post(
            "/splunk/servicesNS/nobody/search/storage/collections/data/splunk_xsoar_users",
            content=json.dumps({"xsoar_user": "admin", "splunk_user": "analyst"}),
            headers={**AUTH, "Content-Type": "application/json"},
        )
        found = rows(client, "| inputlookup splunk_xsoar_users where xsoar_user=admin "
                             "| table splunk_user")
        assert found == [{"splunk_user": "analyst"}]


class TestTheSeededTables:
    """The intel and asset tables agree with the rest of the seed."""

    def test_every_asset_is_a_sentinelone_agent(self, client: TestClient) -> None:
        names = {agent.computerName for agent in store.get_all("agents")}
        assets = rows(client, "| inputlookup mockdr_assets")
        assert assets and {a["nt_host"] for a in assets} == names

    def test_every_malicious_hash_in_the_file_intel_is_on_the_filesystem(
        self, client: TestClient,
    ) -> None:
        found = rows(client,
                     "| tstats count from datamodel=Endpoint.Filesystem "
                     "by Filesystem.file_hash "
                     "| lookup file_intel file_hash AS Filesystem.file_hash OUTPUT threat_key "
                     "| search threat_key=*")
        intel = rows(client, "| inputlookup file_intel")
        assert found and len(found) == len(intel)

    def test_a_detection_host_resolves_to_its_asset_owner(self, client: TestClient) -> None:
        found = rows(client,
                     "| tstats count from datamodel=Malware.Malware_Attacks "
                     "where Malware_Attacks.vendor_product=SentinelOne* "
                     "by Malware_Attacks.dest "
                     "| lookup mockdr_assets nt_host AS Malware_Attacks.dest OUTPUT owner "
                     "| search owner=*")
        assert found, "a SentinelOne detection's host is an asset"


class TestTstatsThroughTheJobApi:
    """tstats agrees with the search it summarises."""

    def test_count_by_sourcetype_matches_stats(self, client: TestClient) -> None:
        summary = rows(client, "| tstats count where index=sentinelone by sourcetype")
        counted = rows(client, "search index=sentinelone | stats count by sourcetype")
        assert summary == counted

    def test_a_data_model_count_matches_its_feeds(self, client: TestClient) -> None:
        total = rows(client, "| tstats count from datamodel=Malware.Malware_Attacks")
        by_vendor = rows(client, "| tstats count from datamodel=Malware "
                                 "by Malware_Attacks.vendor_product")
        assert int(total[0]["count"]) == sum(int(r["count"]) for r in by_vendor)

    def test_the_job_reports_its_results_and_no_events(self, client: TestClient) -> None:
        content = job(client, "| tstats count where index=* by index")
        assert content["resultCount"] > 1 and content["eventCount"] == 0

    def test_the_by_fields_are_declared_as_groups(self, client: TestClient) -> None:
        body = oneshot(client, "| tstats count where index=* by index sourcetype")
        ranks = {f["name"]: f.get("groupby_rank") for f in body["fields"]}
        assert ranks == {"index": "0", "sourcetype": "1", "count": None}

    def test_a_missing_data_model_is_a_failed_search(self, client: TestClient) -> None:
        content = job(client, "| tstats count from datamodel=Nope")
        assert content["dispatchState"] == "FAILED"

    def test_the_data_models_are_listed(self, client: TestClient) -> None:
        body = client.get("/splunk/services/datamodel/model", params={"output_mode": "json"},
                          headers=AUTH).json()
        assert [e["name"] for e in body["entry"]] == [
            "Authentication", "Endpoint", "Intrusion_Detection", "Malware", "Network_Traffic",
        ]
        definition = json.loads(body["entry"][1]["content"]["description"])
        assert definition["objectNameList"] == ["Processes", "Filesystem"]
        assert json.loads(body["entry"][1]["content"]["acceleration"])["enabled"] is True

    def test_one_data_model_is_read_by_name(self, client: TestClient) -> None:
        assert client.get("/splunk/services/datamodel/model/Endpoint",
                          params={"output_mode": "json"}, headers=AUTH).status_code == 200
        assert client.get("/splunk/services/datamodel/model/Nope",
                          params={"output_mode": "json"}, headers=AUTH).status_code == 404


class TestChartAndAppendThroughTheJobApi:
    """The pivot and the subsearch, dispatched as jobs."""

    def test_chart_is_a_transforming_search(self, client: TestClient) -> None:
        content = job(client, "search index=sentinelone | chart count over sourcetype")
        groups = rows(client, "search index=sentinelone | stats count by sourcetype")
        assert content["resultCount"] == len(groups)
        assert content["eventCount"] > content["resultCount"]

    def test_append_adds_the_subsearch(self, client: TestClient) -> None:
        found = rows(client, "search index=sentinelone | stats count "
                             "| append [search index=crowdstrike | stats count]")
        assert len(found) == 2 and found[0] != found[1]

    def test_these_commands_are_no_longer_refused(self, client: TestClient) -> None:
        for search in ("| tstats count", "| inputlookup ip_intel",
                       "| makeresults | lookup ip_intel ip",
                       "| makeresults | chart count", "| makeresults | append [| makeresults]"):
            resp = client.post(JOBS, data={"search": search, "output_mode": "json"},
                               headers=AUTH)
            assert resp.status_code == 201, (search, resp.text)

    def test_the_commands_left_out_are_still_refused(self, client: TestClient) -> None:
        for command in ("transaction", "iplocation"):
            resp = client.post(JOBS, data={"search": f"search * | {command} x",
                                           "output_mode": "json"}, headers=AUTH)
            assert resp.status_code == 400
            assert resp.json()["messages"][0]["text"] == f"Unknown search command '{command}'."
