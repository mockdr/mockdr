"""Behaviours a code review found wrong after they had shipped.

Every one of these returned a `200` carrying something untrue rather than
failing: a finalized search job that went on reporting `QUEUED`, a caller
reported as the `elastic` superuser whoever they were, an import that
confirmed rules it had never created. Each is the failure mode a mock exists
to expose rather than manufacture, so each gets a test that fails loudly if it
comes back.
"""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from application.es_endpoints import commands as endpoint_commands

SPLUNK_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode(),
}
# `analyst`, not `elastic`: the privileges bug was invisible under a caller
# whose name happens to equal the hardcoded fallback.
ES_AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"analyst:mock-analyst-password").decode(),
    "kbn-xsrf": "true",
}
SPLUNK = "/splunk/services/search/jobs"


@pytest.fixture
def dispatch_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hold every job mid-flight, so the reported state is the derived one."""
    from application.splunk.queries import search as search_queries

    monkeypatch.setattr(search_queries, "SPLUNK_DISPATCH_SECONDS", 30.0)


def _dispatch(client: TestClient) -> str:
    return str(client.post(
        SPLUNK, data={"search": "search index=sentinelone"},
        headers=SPLUNK_AUTH, params={"output_mode": "json"},
    ).json()["sid"])


def _state(client: TestClient, sid: str) -> tuple[str, str]:
    content = client.get(
        f"{SPLUNK}/{sid}", headers=SPLUNK_AUTH, params={"output_mode": "json"},
    ).json()["entry"][0]["content"]
    return content["dispatchState"], content["isDone"]


def _control(client: TestClient, sid: str, action: str) -> None:
    client.post(f"{SPLUNK}/{sid}/control", data={"action": action}, headers=SPLUNK_AUTH)


class TestDispatchClockRespectsControlActions:
    """The lifecycle clock must not overwrite an explicit instruction."""

    def test_a_job_starts_at_the_beginning(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        assert _state(client, _dispatch(client)) == ("QUEUED", False)

    def test_finalize_sticks(self, client: TestClient, dispatch_window: None) -> None:
        """Deriving state from elapsed time alone made `finalize` a no-op."""
        sid = _dispatch(client)
        _control(client, sid, "finalize")
        assert _state(client, sid) == ("DONE", True)

    def test_a_cancelled_job_is_gone(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        """splunkd removes a cancelled job rather than marking it failed, so
        the sid stops resolving — which is what a client waits for."""
        sid = _dispatch(client)
        _control(client, sid, "cancel")
        assert client.get(
            f"/splunk/services/search/jobs/{sid}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).status_code == 404

    def test_touch_extends_the_ttl_without_rewinding_the_search(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        """`touch` used to reset the dispatch clock, sending a job backwards."""
        sid = _dispatch(client)
        before = _state(client, sid)
        _control(client, sid, "touch")
        assert _state(client, sid) == before

    def test_a_paused_job_is_not_reported_as_done(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        sid = _dispatch(client)
        _control(client, sid, "pause")
        assert _state(client, sid) == ("PAUSED", False)

    def test_pausing_stops_the_clock(
        self, client: TestClient, dispatch_window: None,
    ) -> None:
        """A held job must not quietly complete while it is held."""
        import time

        from repository.splunk.search_job_repo import search_job_repo

        sid = _dispatch(client)
        _control(client, sid, "pause")
        job = search_job_repo.get(sid)
        assert job is not None

        # Simulate a job dispatched a minute ago that was paused two seconds
        # in. An unpaused job that old would be long past the 30s window.
        job.published_at = time.time() - 60.0
        job.paused_at = job.published_at + 2.0
        search_job_repo.save(job)
        assert _state(client, sid) == ("PAUSED", False)

        _control(client, sid, "unpause")
        # Resumes two seconds in, where it stopped — not at the end.
        assert _state(client, sid) == ("QUEUED", False)


class TestKibanaReportsTheTruth:
    """Routes that answered `200` with something that was not so."""

    def test_privileges_name_the_actual_caller(self, client: TestClient) -> None:
        """The auth context spells it `user`; reading `username` always missed."""
        body = client.get("/kibana/api/detection_engine/privileges", headers=ES_AUTH).json()
        assert body["username"] == "analyst"

    def test_bulk_create_accepts_a_risk_score_of_zero(self, client: TestClient) -> None:
        """`not entry.get(f)` rejected a supplied 0 as `"undefined"`."""
        body = client.post(
            "/kibana/api/detection_engine/rules/_bulk_create", headers=ES_AUTH,
            json=[{
                "name": "Zero risk", "description": "d", "type": "query",
                "severity": "low", "risk_score": 0, "rule_id": "zero-risk-rule",
            }],
        ).json()
        assert "error" not in body[0], body[0]
        assert body[0]["risk_score"] == 0

    def test_bulk_create_still_rejects_an_absent_field(self, client: TestClient) -> None:
        body = client.post(
            "/kibana/api/detection_engine/rules/_bulk_create", headers=ES_AUTH,
            json=[{"name": "No severity", "description": "d", "type": "query"}],
        ).json()
        assert body[0]["error"]["status_code"] == 400

    def test_an_unknown_space_is_a_404(self, client: TestClient) -> None:
        """Falling back to the default space confirmed ids that do not exist."""
        resp = client.get("/kibana/api/spaces/space/no-such-space", headers=ES_AUTH)
        assert resp.status_code == 404

    def test_the_default_space_is_still_served(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/spaces/space/default", headers=ES_AUTH)
        assert resp.status_code == 200
        assert resp.json()["id"] == "default"

    def test_an_exception_summary_needs_a_list_to_summarise(
        self, client: TestClient,
    ) -> None:
        """All-zero counts were indistinguishable from an empty list."""
        resp = client.get("/kibana/api/exception_lists/summary", headers=ES_AUTH)
        assert resp.status_code == 400
        # And in 8.15's words, which the two exception-list routes beside
        # this one already used: it said `list_id: Required`.
        assert resp.json()["message"] == "id or list_id required"


class TestEndpointActions:
    """What is pending, and in what order it happened."""

    @staticmethod
    def _agent(client: TestClient) -> str:
        listing = client.get("/kibana/api/endpoint/metadata", headers=ES_AUTH).json()
        return str(listing["data"][0]["metadata"]["agent"]["id"])

    def test_pending_actions_name_the_action(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Everything pending was filed under `isolate`, whatever it was."""
        # An action settles a second after it is issued, and a loaded test
        # run can spend that second between the two calls below. This test
        # is about what a pending action is called, not about when it stops
        # being one.
        monkeypatch.setattr(endpoint_commands, "_SETTLE_SECONDS", 3600.0)
        agent = self._agent(client)
        client.post(
            # 8.15 serves this only under `/action/` — measured.
            "/kibana/api/endpoint/action/kill_process", headers=ES_AUTH,
            json={"endpoint_ids": [agent], "parameters": {"pid": 42}},
        )
        pending = client.get(
            "/kibana/api/endpoint/action_status", headers=ES_AUTH,
            params={"agent_ids": agent},
        ).json()["data"][0]["pending_actions"]
        assert pending.get("kill-process") == 1, pending
        assert "isolate" not in pending

    def test_the_action_log_is_newest_first(self, client: TestClient) -> None:
        """It documented newest-first and served repository insertion order."""
        agent = self._agent(client)
        for comment in ("older", "newer"):
            client.post(
                "/kibana/api/endpoint/isolate", headers=ES_AUTH,
                json={"endpoint_ids": [agent], "comment": comment},
            )
        entries = client.get(
            f"/kibana/api/endpoint/action_log/{agent}", headers=ES_AUTH,
            params={
                "start_date": "2020-01-01T00:00:00.000Z",
                "end_date": "2030-01-01T00:00:00.000Z",
            },
        ).json()["data"]
        stamps = [e["started_at"] for e in entries]
        assert len(stamps) >= 2
        assert stamps == sorted(stamps, reverse=True)


class TestRuleImportActuallyImports:
    """`_import` read no body and reported success for zero rules."""

    @staticmethod
    def _export(client: TestClient) -> str:
        """Export the rules by name — `objects` is required, and an empty
        selection exports nothing rather than everything."""
        found = client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"per_page": 10_000},
        ).json()["data"]
        return client.post(
            "/kibana/api/detection_engine/rules/_export", headers=ES_AUTH,
            json={"objects": [{"rule_id": r["rule_id"]} for r in found]},
        ).text

    @staticmethod
    def _count(client: TestClient) -> int:
        return int(client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"per_page": 1},
        ).json()["total"])

    def test_a_new_rule_is_created(self, client: TestClient) -> None:
        before = self._count(client)
        payload = json.dumps({
            "rule_id": "brand-new-imported", "name": "New", "description": "d",
            "type": "query", "severity": "low", "risk_score": 10,
        })
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            content=payload.encode(),
        ).json()
        assert body["success"] is True
        assert body["success_count"] == 1
        assert self._count(client) == before + 1

    def test_re_importing_an_export_reports_conflicts(self, client: TestClient) -> None:
        """Silence here made a failed migration look like a successful one."""
        ndjson = self._export(client)
        rules = len([line for line in ndjson.splitlines() if line.strip()]) - 1
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            content=ndjson.encode(),
        ).json()
        assert body["rules_count"] == rules
        assert body["success_count"] == 0
        assert body["success"] is False
        assert len(body["errors"]) == rules
        assert body["errors"][0]["error"]["status_code"] == 409

    def test_overwrite_replaces_them(self, client: TestClient) -> None:
        ndjson = self._export(client)
        rules = len([line for line in ndjson.splitlines() if line.strip()]) - 1
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            params={"overwrite": "true"}, content=ndjson.encode(),
        ).json()
        assert body["success"] is True
        assert body["success_count"] == rules

    def test_the_export_summary_line_is_not_counted_as_a_rule(
        self, client: TestClient,
    ) -> None:
        ndjson = self._export(client)
        summary = json.loads(ndjson.strip().splitlines()[-1])
        assert "exported_count" in summary
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            params={"overwrite": "true"}, content=ndjson.encode(),
        ).json()
        assert body["rules_count"] == summary["exported_count"]

    def test_a_multipart_upload_works_too(self, client: TestClient) -> None:
        """Kibana's own UI posts the file as multipart, not as a raw body."""
        before = self._count(client)
        payload = json.dumps({
            "rule_id": "multipart-imported", "name": "Multipart", "description": "d",
            "type": "query", "severity": "low", "risk_score": 10,
        })
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            files={"file": ("rules.ndjson", payload, "application/ndjson")},
        ).json()
        assert body["success_count"] == 1
        assert self._count(client) == before + 1

    def test_a_malformed_line_is_reported_not_swallowed(
        self, client: TestClient,
    ) -> None:
        body = client.post(
            "/kibana/api/detection_engine/rules/_import", headers=ES_AUTH,
            content=b"{not json at all\n",
        ).json()
        assert body["success"] is False
        assert body["errors"][0]["error"]["status_code"] == 400


class TestKibanaRecordsWhoWroteARule:
    """`created_by` and `updated_by` name the caller, not the superuser.

    Every rule write recorded `elastic` whoever had called — the same failure
    `/privileges` had when it reported the caller as `elastic` too, and
    invisible for exactly the same reason: `elastic` is a plausible answer.
    """

    RULE = {
        "name": "Who wrote this", "description": "d", "type": "query",
        "query": "*", "severity": "low", "risk_score": 5,
    }

    def test_a_created_rule_names_its_author(self, client: TestClient) -> None:
        body = client.post(
            "/kibana/api/detection_engine/rules", headers=ES_AUTH, json=self.RULE,
        ).json()
        assert body["created_by"] == "analyst"
        assert body["updated_by"] == "analyst"

    def test_a_patch_names_who_patched(self, client: TestClient) -> None:
        created = client.post(
            "/kibana/api/detection_engine/rules", headers=ES_AUTH,
            json={**self.RULE, "rule_id": "authored-by-analyst"},
        ).json()
        patched = client.patch(
            "/kibana/api/detection_engine/rules", headers=ES_AUTH,
            json={"rule_id": created["rule_id"], "name": "renamed"},
        ).json()
        assert patched["updated_by"] == "analyst"

    def test_a_bulk_enable_names_who_enabled(self, client: TestClient) -> None:
        created = client.post(
            "/kibana/api/detection_engine/rules", headers=ES_AUTH,
            json={**self.RULE, "rule_id": "bulk-authored", "enabled": False},
        ).json()
        client.post(
            "/kibana/api/detection_engine/rules/_bulk_action", headers=ES_AUTH,
            json={"action": "enable", "ids": [created["id"]]},
        )
        read = client.get(
            "/kibana/api/detection_engine/rules", headers=ES_AUTH,
            params={"rule_id": created["rule_id"]},
        ).json()
        assert read["updated_by"] == "analyst"


class TestAJobNamesItsOwnQuery:
    """What a client reads back after dispatching a search."""

    def test_the_job_reports_the_search_it_was_given(self, client: TestClient) -> None:
        """It reported the query the recorded fixture had been dispatched with.

        `search`, `request` and `eventSearch` all came from
        `search_jobs.json`, so a client polling a job it had just created
        read back `search index=_internal | head 5` under HTTP 200.
        """
        query = "search index=sentinelone | head 3"
        sid = client.post(
            SPLUNK, data={"search": query}, headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()["sid"]

        content = client.get(
            f"{SPLUNK}/{sid}", headers=SPLUNK_AUTH, params={"output_mode": "json"},
        ).json()["entry"][0]["content"]

        assert content["search"] == query
        assert content["eventSearch"] == query
        assert content["request"] == {"search": query}

    def test_the_job_echoes_the_arguments_it_was_sent_and_no_others(
        self, client: TestClient,
    ) -> None:
        """splunkd repeats the dispatch arguments verbatim, `output_mode` aside."""
        sid = client.post(
            SPLUNK, data={"search": "search index=sentinelone", "exec_mode": "blocking"},
            headers=SPLUNK_AUTH, params={"output_mode": "json"},
        ).json()["sid"]

        request = client.get(
            f"{SPLUNK}/{sid}", headers=SPLUNK_AUTH, params={"output_mode": "json"},
        ).json()["entry"][0]["content"]["request"]

        assert request["exec_mode"] == "blocking"
        assert "output_mode" not in request

    def test_events_carry_what_splunkd_stamps_on_them(self, client: TestClient) -> None:
        """`/events` served neither the internal members nor only the indexed ones.

        A client de-duplicating on `_cd` or locating an event through `_si`
        found nothing to read; what it did find were the fields mockdr had
        parsed out of `_raw`, which `/events` does not carry.
        """
        sid = client.post(
            SPLUNK, data={"search": "search index=sentinelone"}, headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()["sid"]

        events = client.get(
            f"{SPLUNK}/{sid}/events", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "count": 2},
        ).json()["results"]

        assert events, "the seeded index should have matched something"
        stamped = {
            "_bkt", "_cd", "_indextime", "_serial", "_si", "_sourcetype",
            "linecount", "splunk_server",
        }
        assert stamped <= set(events[0])
        assert events[0]["_serial"] == "0"
        assert events[0]["_si"] == ["mockdr-splunk", events[0].get("index", "main")]
        # And nothing beyond what splunkd keeps with the event.
        assert set(events[0]) <= stamped | {
            "_raw", "_time", "host", "index", "source", "sourcetype",
        }


class TestAnUnknownQueryMemberIsRefused:
    """8.15 checks the query schema before the handler runs."""

    @pytest.mark.parametrize(("path", "message"), [
        ("/kibana/api/status", "[request query.zzz]: definition for this key is missing"),
        ("/kibana/api/cases/tags", 'invalid keys "zzz,qqq"'),
        (
            "/kibana/api/timeline",
            '[request query]: Invalid value {"zzz":"1","qqq":"2"}, '
            'excess properties: ["zzz","qqq"]',
        ),
    ])
    def test_each_validator_words_it_the_way_kibana_does(
        self, client: TestClient, path: str, message: str,
    ) -> None:
        """Three validators, three wordings — measured on 8.15."""
        resp = client.get(path, headers=ES_AUTH, params={"zzz": "1", "qqq": "2"})

        assert resp.status_code == 400
        assert resp.json()["message"] == message

    def test_a_member_the_route_reads_is_not_refused(self, client: TestClient) -> None:
        """The route's own members are allowed, whatever the measured list holds."""
        assert client.get(
            "/kibana/api/status", headers=ES_AUTH, params={"v8format": "true"},
        ).status_code == 200

    def test_the_action_filter_is_spelled_the_way_kibana_spells_it(
        self, client: TestClient,
    ) -> None:
        """mockdr took `agent_id`, which 8.15 refuses outright."""
        assert client.get(
            "/kibana/api/endpoint/action", headers=ES_AUTH, params={"agent_id": "x"},
        ).status_code == 400
        assert client.get(
            "/kibana/api/endpoint/action", headers=ES_AUTH, params={"agentIds": "x"},
        ).status_code == 200


class TestAListingNamesNothingItCannotServe:
    """splunklib lists a collection and then reads one entry by name."""

    @pytest.mark.parametrize(("collection", "entry"), [
        ("authorization/roles", "admin"),
        ("authorization/capabilities", "capabilities"),
        ("server/settings", "settings"),
        ("admin/macros", "notable"),
    ])
    def test_every_entry_a_listing_names_can_be_read_back(
        self, client: TestClient, collection: str, entry: str,
    ) -> None:
        """Each of these listed something nothing would serve, so the read 404'd."""
        listed = client.get(
            f"/splunk/services/{collection}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()
        assert entry in [e["name"] for e in listed["entry"]]

        one = client.get(
            f"/splunk/services/{collection}/{entry}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )

        assert one.status_code == 200
        assert [e["name"] for e in one.json()["entry"]] == [entry]

    def test_a_single_read_names_what_the_entry_accepts(
        self, client: TestClient,
    ) -> None:
        """The `fields` block belongs to the single read, not to the listing.

        mockdr sent an empty one on both, so a client reading
        `fields.optional` to learn what it may write learned nothing.
        """
        one = client.get(
            "/splunk/services/authentication/users/admin", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()["entry"][0]
        listed = client.get(
            "/splunk/services/authentication/users", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()["entry"][0]

        assert "roles" in one["fields"]["optional"]
        assert "password" in one["fields"]["optional"]
        assert "fields" not in listed

    def test_an_entry_that_is_not_there_is_still_a_refusal(
        self, client: TestClient,
    ) -> None:
        """A name nothing defines is 404, not an empty entry list."""
        for path in ("authorization/roles/nosuch", "admin/macros/nosuch"):
            resp = client.get(
                f"/splunk/services/{path}", headers=SPLUNK_AUTH,
                params={"output_mode": "json"},
            )
            assert resp.status_code == 404, path
            assert "nosuch" in resp.json()["messages"][0]["text"]


class TestAnUnknownClusterParameterIsRefused:
    """Elasticsearch refuses what it does not recognise, before running it."""

    ES = {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
    }

    def test_a_misspelled_size_is_refused_not_ignored(
        self, client: TestClient,
    ) -> None:
        """`siz` for `size` read as an unfiltered result set under HTTP 200."""
        resp = client.get("/elastic/_search", headers=self.ES, params={"siz": "1"})

        assert resp.status_code == 400
        reason = resp.json()["error"]["reason"]
        assert reason == "request [/_search] contains unrecognized parameter: [siz]"
        assert resp.json()["error"]["type"] == "illegal_argument_exception"
        assert resp.json()["status"] == 400

    def test_several_are_named_alphabetically_not_as_sent(
        self, client: TestClient,
    ) -> None:
        """Measured on 8.15: sorted, and the plural form."""
        resp = client.get(
            "/elastic/_cluster/health", headers=self.ES,
            params=[("zzz", "1"), ("aaa", "2"), ("mmm", "3")],
        )

        assert resp.json()["error"]["reason"] == (
            "request [/_cluster/health] contains unrecognized parameters: "
            "[aaa], [mmm], [zzz]"
        )

    def test_the_message_names_the_path_the_cluster_would_have_seen(
        self, client: TestClient,
    ) -> None:
        """Not mockdr's `/elastic` mount, which no cluster has."""
        resp = client.get(
            "/elastic/.siem-signals/_search", headers=self.ES, params={"zzz": "1"},
        )

        assert "/elastic" not in resp.json()["error"]["reason"]
        assert "[/.siem-signals/_search]" in resp.json()["error"]["reason"]

    def test_a_parameter_the_cluster_takes_is_not_refused(
        self, client: TestClient,
    ) -> None:
        assert client.get(
            "/elastic/_search", headers=self.ES,
            params={"size": "1", "from": "0", "track_total_hits": "true"},
        ).status_code == 200

    def test_source_content_type_is_known_only_beside_source(
        self, client: TestClient,
    ) -> None:
        """It is unrecognised on its own — which one-at-a-time asking missed."""
        alone = client.get(
            "/elastic/_search", headers=self.ES,
            params={"source_content_type": "application/json"},
        )
        assert alone.status_code == 400
        assert "source_content_type" in alone.json()["error"]["reason"]

        beside = client.get(
            "/elastic/_search", headers=self.ES,
            params={"source": '{"query":{"match_all":{}}}',
                    "source_content_type": "application/json"},
        )
        assert beside.status_code == 200

    def test_a_write_is_refused_before_it_acts(self, client: TestClient) -> None:
        """The sharpest shape of it: mockdr deleted on a request the cluster
        refuses, so a client with a typo lost data here that production keeps."""
        index = "mockdr-refusal-probe"
        client.put(f"/elastic/{index}", headers=self.ES, json={})
        client.put(f"/elastic/{index}/_doc/a", headers=self.ES,
                   json={"host": "probe"}, params={"refresh": "true"})

        refused = client.request(
            "DELETE", f"/elastic/{index}/_doc/a", headers=self.ES,
            params={"zzzqqq": "1"},
        )

        assert refused.status_code == 400
        assert "unrecognized parameter" in refused.json()["error"]["reason"]
        # And the document is still there, which is the half that matters.
        assert client.get(f"/elastic/{index}/_doc/a", headers=self.ES).status_code == 200
        client.request("DELETE", f"/elastic/{index}", headers=self.ES)

    def test_the_index_survives_a_refused_delete(self, client: TestClient) -> None:
        index = "mockdr-refusal-probe-2"
        client.put(f"/elastic/{index}", headers=self.ES, json={})

        assert client.request(
            "DELETE", f"/elastic/{index}", headers=self.ES, params={"zzzqqq": "1"},
        ).status_code == 400
        assert client.get(f"/elastic/{index}", headers=self.ES).status_code == 200
        client.request("DELETE", f"/elastic/{index}", headers=self.ES)

    def test_the_cat_pattern_is_a_path_segment_not_a_parameter(
        self, client: TestClient,
    ) -> None:
        """Two routes share one handler, so `pattern` became a query member."""
        assert client.get(
            "/elastic/_cat/indices", headers=self.ES, params={"pattern": "x*"},
        ).status_code == 400
        assert client.get(
            "/elastic/_cat/indices/sentinelone", headers=self.ES,
        ).status_code == 200


class TestAnUnknownSplunkArgumentIsRefused:
    """splunkd refuses an argument its handler does not take."""

    @pytest.mark.parametrize("collection", [
        "authorization/capabilities", "admin/macros", "saved/eventtypes",
        "server/health/splunkd", "data/inputs/monitor", "kvstore/status",
    ])
    def test_the_collections_that_used_to_ignore_it_refuse_it(
        self, client: TestClient, collection: str,
    ) -> None:
        resp = client.get(
            f"/splunk/services/{collection}", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "zzz": "1"},
        )

        assert resp.status_code == 400
        assert resp.json()["messages"][0]["text"] == (
            'Argument "zzz" is not supported by this handler.'
        )

    def test_the_alphabetically_first_is_named(self, client: TestClient) -> None:
        """Not the first one sent — measured with the two swapped."""
        for order in ([("zzz", "1"), ("aaa", "2")], [("aaa", "2"), ("zzz", "1")]):
            resp = client.get(
                "/splunk/services/admin/macros", headers=SPLUNK_AUTH,
                params=[("output_mode", "json"), *order],
            )
            assert resp.json()["messages"][0]["text"] == (
                'Argument "aaa" is not supported by this handler.'
            )

    def test_add_orphan_field_belongs_to_saved_searches_alone(
        self, client: TestClient,
    ) -> None:
        """It was in the set every collection shares, and is not."""
        assert client.get(
            "/splunk/services/server/info", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "add_orphan_field": "true"},
        ).status_code == 400
        assert client.get(
            "/splunk/services/saved/searches", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "add_orphan_field": "true"},
        ).status_code == 200

    def test_the_longer_collection_path_wins_the_prefix(
        self, client: TestClient,
    ) -> None:
        """`data/indexes` takes `summarize`; `data/indexes-extended` does not."""
        assert client.get(
            "/splunk/services/data/indexes", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "summarize": "false"},
        ).status_code == 200
        assert client.get(
            "/splunk/services/data/indexes-extended", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "summarize": "false"},
        ).status_code == 400


class TestTheResponseActionsKibanaRoutes:
    """Nine commands, and the order their schema asks in."""

    @staticmethod
    def _agent(client: TestClient) -> str:
        listing = client.get("/kibana/api/endpoint/metadata", headers=ES_AUTH).json()
        return str(listing["data"][0]["metadata"]["agent"]["id"])

    @pytest.mark.parametrize(("action", "command", "parameters"), [
        ("suspend_process", "suspend-process", {"pid": 42}),
        ("running_procs", "running-processes", None),
        ("get_file", "get-file", {"path": "/etc/passwd"}),
        ("execute", "execute", {"command": "whoami"}),
    ])
    def test_the_four_actions_that_answered_404_now_run(
        self, client: TestClient, action: str, command: str, parameters: dict | None,
    ) -> None:
        """A playbook running any of them met a 404 from a product that routes it."""
        agent = self._agent(client)
        body: dict = {"endpoint_ids": [agent], "comment": "why"}
        if parameters is not None:
            body["parameters"] = parameters

        resp = client.post(
            f"/kibana/api/endpoint/action/{action}", headers=ES_AUTH, json=body,
        )

        assert resp.status_code == 200, resp.text
        # Kibana's own command vocabulary is hyphenated — the one its
        # `commands` filter validates against.
        assert resp.json()["action"] == command
        assert resp.json()["agent_id"] == agent

    def test_parameters_are_checked_where_the_schema_declares_them(
        self, client: TestClient,
    ) -> None:
        """Before `agent_type`, which is declared after them, and before the
        members the schema has no definition for."""
        agent = self._agent(client)
        by_type = client.post(
            "/kibana/api/endpoint/action/scan", headers=ES_AUTH,
            json={"endpoint_ids": [agent], "agent_type": "nope"},
        )
        assert by_type.json()["message"] == (
            "[request body.parameters.path]: expected value of type [string] "
            "but got [undefined]"
        )

        by_key = client.post(
            "/kibana/api/endpoint/action/kill_process", headers=ES_AUTH,
            json={"endpoint_ids": [agent], "zzzqqq": 1},
        )
        assert by_key.json()["message"] == (
            "[request body.parameters]: expected at least one defined value "
            "but got [undefined]"
        )

    def test_a_process_block_naming_neither_member_fails_both_arms(
        self, client: TestClient,
    ) -> None:
        """It read as one failure; Kibana reports the first of each arm."""
        resp = client.post(
            "/kibana/api/endpoint/action/suspend_process", headers=ES_AUTH,
            json={"endpoint_ids": [self._agent(client)], "parameters": {}},
        )

        assert resp.json()["message"] == (
            "[request body.parameters]: types that failed validation:\n"
            "- [request body.parameters.0.pid]: expected value of type [number] "
            "but got [undefined]\n"
            "- [request body.parameters.1.entity_id]: expected value of type "
            "[string] but got [undefined]"
        )

    def test_an_action_that_declares_no_parameters_refuses_every_member(
        self, client: TestClient,
    ) -> None:
        """`isolate` takes the block and declares nothing inside it."""
        resp = client.post(
            "/kibana/api/endpoint/action/isolate", headers=ES_AUTH,
            json={"endpoint_ids": [self._agent(client)], "parameters": {"path": "/tmp"}},
        )

        assert resp.status_code == 400
        assert resp.json()["message"] == (
            "[request body.parameters.path]: definition for this key is missing"
        )

    def test_execute_declares_a_numeric_timeout(self, client: TestClient) -> None:
        resp = client.post(
            "/kibana/api/endpoint/action/execute", headers=ES_AUTH,
            json={"endpoint_ids": [self._agent(client)],
                  "parameters": {"command": "ls", "timeout": "soon"}},
        )

        assert resp.status_code == 400
        assert "[request body.parameters.timeout]" in resp.json()["message"]


class TestTheVerbDecidesBeforeThePath:
    """splunkd's answer to a verb a path does not take."""

    @pytest.mark.parametrize(("method", "path", "status", "kind", "text"), [
        ("PUT", "authorization/roles", 404, "ERROR", "Requested invalid action 'PUT'."),
        ("PUT", "data/indexes", 404, "ERROR", "Requested invalid action 'PUT'."),
        ("PUT", "storage/collections/config", 404, "ERROR",
         "Requested invalid action 'PUT'."),
        ("PATCH", "authorization/roles", 405, "ERROR", "Method Not Allowed"),
        ("PATCH", "server/settings", 405, "ERROR", "Method Not Allowed"),
        ("PUT", "search/jobs", 405, "ERROR", "Method Not Allowed"),
        ("PATCH", "search/typeahead", 405, "ERROR", "Method Not Allowed"),
        ("DELETE", "search/jobs", 405, "FATAL", "Method Not Allowed"),
    ])
    def test_each_one_answers_what_splunkd_answers(
        self, client: TestClient, method: str, path: str, status: int,
        kind: str, text: str,
    ) -> None:
        """It answered the 400 splunkd keeps for a POST with no name, for all
        of them."""
        resp = client.request(
            method, f"/splunk/services/{path}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )

        assert resp.status_code == status
        assert resp.json()["messages"][0] == {"type": kind, "text": text}

    def test_only_the_search_delete_names_what_the_path_takes(
        self, client: TestClient,
    ) -> None:
        """Of the three refusals here, one carries an Allow header."""
        with_allow = client.request(
            "DELETE", "/splunk/services/search/jobs", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )
        without = client.request(
            "PATCH", "/splunk/services/authorization/roles", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )

        assert with_allow.headers["allow"] == "GET,POST,HEAD"
        assert "allow" not in without.headers

    def test_the_batch_paths_take_put_as_well_as_post(
        self, client: TestClient,
    ) -> None:
        """splunkd's own 405 there names `Allow: POST,PUT`; mockdr served one."""
        resp = client.put(
            "/splunk/servicesNS/nobody/search/storage/collections/data/probe_kv/batch_save",
            headers=SPLUNK_AUTH, json=[{"_key": "a", "v": 1}],
        )

        assert resp.status_code != 405

    def test_deleting_a_job_is_cancelling_it(self, client: TestClient) -> None:
        """splunkd says so without naming the sid; mockdr echoed it back."""
        sid = client.post(
            SPLUNK, data={"search": "search index=sentinelone"}, headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()["sid"]

        resp = client.request(
            "DELETE", f"{SPLUNK}/{sid}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )

        assert resp.json()["messages"][0]["text"] == "Search job cancelled."


class TestAnAliasOnOneIndex:
    """The routes that are about one alias, and the HEAD that asks about it."""

    ES = {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
    }
    INDEX = "mockdr-alias-probe"

    @pytest.fixture
    def index(self, client: TestClient) -> str:
        client.put(f"/elastic/{self.INDEX}", headers=self.ES, json={})
        client.put(f"/elastic/{self.INDEX}/_alias/probe-alias", headers=self.ES)
        yield self.INDEX
        client.request("DELETE", f"/elastic/{self.INDEX}", headers=self.ES)

    def test_one_alias_on_one_index_is_served(
        self, client: TestClient, index: str,
    ) -> None:
        """mockdr had the route under two other spellings and not this one."""
        resp = client.get(f"/elastic/{index}/_alias/probe-alias", headers=self.ES)

        assert resp.status_code == 200
        assert resp.json() == {index: {"aliases": {"probe-alias": {}}}}

    def test_an_alias_the_index_does_not_carry_is_a_bare_envelope(
        self, client: TestClient, index: str,
    ) -> None:
        """404 `alias [x] missing`, without the nested `error` object."""
        resp = client.get(f"/elastic/{index}/_alias/nosuch", headers=self.ES)

        assert resp.status_code == 404
        assert resp.json() == {"error": "alias [nosuch] missing", "status": 404}

    def test_head_answers_the_question_it_is_asking(
        self, client: TestClient, index: str,
    ) -> None:
        """`_source` is an existence endpoint and was not in mockdr's list."""
        client.put(f"/elastic/{index}/_doc/a", headers=self.ES,
                   json={"host": "probe"}, params={"refresh": "true"})

        assert client.head(f"/elastic/{index}/_source/a", headers=self.ES
                           ).status_code == 200
        assert client.head(f"/elastic/{index}/_source/zzz", headers=self.ES
                           ).status_code == 404
        assert client.head(f"/elastic/{index}/_alias/probe-alias", headers=self.ES
                           ).status_code == 200
        assert client.head(f"/elastic/{index}/_alias/nosuch", headers=self.ES
                           ).status_code == 404

    def test_the_index_itself_reports_what_it_is_called_by(
        self, client: TestClient, index: str,
    ) -> None:
        """`GET /{index}` built an empty alias block instead of reading one."""
        body = client.get(f"/elastic/{index}", headers=self.ES).json()

        assert body[index]["aliases"] == {"probe-alias": {}}


class TestAnEmptyClauseIsNotAMatchAll:
    """What the cluster answers to a query that names nothing."""

    ES = {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
    }

    def test_an_empty_query_is_refused_not_answered_with_everything(
        self, client: TestClient,
    ) -> None:
        """It returned every document — a search that looks like it worked and
        gives the opposite of what an empty filter should."""
        resp = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={"query": {}},
        )

        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["type"] == "illegal_argument_exception"
        assert error["reason"] == "query malformed, empty clause found at [1:11]"

    def test_count_words_it_its_own_way(self, client: TestClient) -> None:
        """`Failed to parse`, the position as fields of its own, and the
        search's wording underneath as the cause."""
        error = client.post(
            "/elastic/.siem-signals/_count", headers=self.ES, json={"query": {}},
        ).json()["error"]

        assert error["type"] == "parsing_exception"
        assert error["reason"] == "Failed to parse"
        assert (error["line"], error["col"]) == (1, 11)
        assert error["caused_by"] == {
            "type": "illegal_argument_exception",
            "reason": "query malformed, empty clause found at [1:11]",
        }

    def test_validate_answers_rather_than_refuses(self, client: TestClient) -> None:
        """The same body is this route's whole subject."""
        resp = client.post(
            "/elastic/.siem-signals/_validate/query", headers=self.ES,
            json={"query": {}},
        )

        assert resp.status_code == 200
        assert resp.json() == {"valid": False}

    @pytest.mark.parametrize(("clause", "kind", "reason"), [
        ("term", "illegal_argument_exception", "field name is null or empty"),
        ("prefix", "illegal_argument_exception", "field name is null or empty"),
        ("fuzzy", "illegal_argument_exception", "field name cannot be null or empty"),
        ("match", "parsing_exception", "No text specified for text query"),
        ("exists", "parsing_exception", "[exists] must be provided with a [field]"),
        ("query_string", "parsing_exception",
         "[query_string] must be provided with a [query]"),
        ("boosting", "parsing_exception",
         "[boosting] query requires 'positive' query to be set'"),
    ])
    def test_an_empty_clause_body_is_refused_by_name(
        self, client: TestClient, clause: str, kind: str, reason: str,
    ) -> None:
        """Twelve of these reached a builder that assumed a first key and came
        back 500."""
        resp = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"query": {clause: {}}},
        )

        assert resp.status_code == 400
        assert resp.json()["error"]["type"] == kind
        assert resp.json()["error"]["reason"] == reason

    @pytest.mark.parametrize("clause", ["bool", "ids", "match_all"])
    def test_the_three_that_take_an_empty_body_still_do(
        self, client: TestClient, clause: str,
    ) -> None:
        assert client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"query": {clause: {}}},
        ).status_code == 200

    @pytest.mark.parametrize("arm", ["must", "should", "must_not", "filter"])
    def test_an_empty_clause_inside_a_bool_is_refused_too(
        self, client: TestClient, arm: str,
    ) -> None:
        """It matched everything, so a `must` built from a filter that matched
        nothing selected the whole index."""
        resp = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"query": {"bool": {arm: [{}]}}},
        )

        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["type"] == "x_content_parse_exception"
        assert error["reason"].endswith(f"[bool] failed to parse field [{arm}]")
        assert error["caused_by"]["type"] == "illegal_argument_exception"
        assert "empty clause found at" in error["caused_by"]["reason"]


class TestAnAggregationThatNamesNothing:
    """Fourteen of fifteen types refuse an empty body; mockdr ran them."""

    ES = {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
    }

    @pytest.mark.parametrize("agg", [
        "terms", "date_histogram", "histogram", "range", "missing",
        "avg", "cardinality", "max", "min", "stats", "sum", "value_count",
    ])
    def test_an_empty_body_is_refused(self, client: TestClient, agg: str) -> None:
        """A `terms` with no field grouped every document into one bucket and
        reported that as the answer."""
        resp = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {agg: {}}}},
        )

        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["type"] == "illegal_argument_exception"
        # The trailing space after the full stop is Elasticsearch's own.
        assert error["reason"] == (
            "Required one of fields [field, script], but none were specified. "
        )

    def test_filters_says_it_its_own_way(self, client: TestClient) -> None:
        error = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {"filters": {}}}},
        ).json()["error"]

        assert error["type"] == "illegal_argument_exception"
        assert error["reason"] == "[filters] cannot be empty."

    def test_a_filter_on_nothing_is_the_searchs_own_empty_clause(
        self, client: TestClient,
    ) -> None:
        error = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {"filter": {}}}},
        ).json()["error"]

        assert error["type"] == "illegal_argument_exception"
        assert error["reason"].startswith("query malformed, empty clause found at [1:")

    def test_top_hits_takes_an_empty_body(self, client: TestClient) -> None:
        assert client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {"top_hits": {}}}},
        ).status_code == 200

    def test_naming_none_and_naming_two_are_different_complaints(
        self, client: TestClient,
    ) -> None:
        """mockdr made one of them, for both."""
        none = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {}}},
        ).json()["error"]
        two = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {
                "max": {"field": "sev"}, "min": {"field": "sev"}}}},
        ).json()["error"]

        assert none["reason"] == "Missing definition for aggregation [a]"
        assert two["reason"] == (
            "Found two aggregation type definitions in [a]: [max] and [min]"
        )
        # And neither carries the cause an unknown *type* does.
        assert "caused_by" not in none
        assert "caused_by" not in two

    def test_an_unknown_type_still_carries_its_cause(
        self, client: TestClient,
    ) -> None:
        error = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {"nosuchagg": {}}}},
        ).json()["error"]

        assert error["reason"] == "Unknown aggregation type [nosuchagg]"
        assert error["caused_by"]["type"] == "named_object_not_found_exception"


class TestSettingAnAlertStatus:
    """The route a SOAR uses to close an alert."""

    @pytest.mark.parametrize(("body", "message"), [
        ({}, "[request body]: signal_ids: Required, status: Required, "
             "query: Required, status: Required"),
        ({"signal_ids": ["a"]},
         "[request body]: status: Required, query: Required, status: Required"),
        ({"status": "open"},
         "[request body]: signal_ids: Required, query: Required"),
        ({"signal_ids": [], "status": "open"},
         "[request body]: signal_ids: Array must contain at least 1 element(s)"),
        ({"signal_ids": "a", "status": "open"},
         "[request body]: signal_ids: Expected array, received string, query: Required"),
    ])
    def test_each_arm_of_the_union_is_named(
        self, client: TestClient, body: dict, message: str,
    ) -> None:
        """It answered one hand-written line for all of these."""
        resp = client.post(
            "/kibana/api/detection_engine/signals/status", headers=ES_AUTH, json=body,
        )

        assert resp.status_code == 400
        assert resp.json()["message"] == message

    def test_an_unknown_status_lists_the_ones_it_takes(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            "/kibana/api/detection_engine/signals/status", headers=ES_AUTH,
            json={"signal_ids": ["a"], "status": "nope"},
        )

        assert "Expected 'open' | 'closed' | 'acknowledged' | 'in-progress'" in (
            resp.json()["message"]
        )

    @pytest.mark.parametrize("body", [
        {"signal_ids": ["a"], "status": "open"},
        {"query": {"match_all": {}}, "status": "closed"},
        {"signal_ids": ["a"], "status": "acknowledged", "zzzqqq": 1},
    ])
    def test_one_satisfied_arm_is_enough(
        self, client: TestClient, body: dict,
    ) -> None:
        """And an undeclared member is stripped rather than refused — zod."""
        assert client.post(
            "/kibana/api/detection_engine/signals/status", headers=ES_AUTH, json=body,
        ).status_code == 200


class TestACommandGivenNoArgument:
    """Ten SPL commands ran on nothing and answered the rows unchanged."""

    @pytest.mark.parametrize(("command", "text"), [
        ("sort", "You must specify fields to sort."),
        ("table", "Error in 'table' command: Must specify at least one valid "
                  "field name (can contain wildcards)."),
        ("eval", "Error in 'eval' command: Arguments are missing. "
                 "Usage: eval dest_key = expression."),
        ("dedup", "Error in 'dedup' command: At least one field must be given "
                  "as an argument."),
        ("top", "Error in 'top' command: No fields were specified."),
        ("rare", "Error in 'rare' command: No fields were specified."),
        ("rename", "Error in 'rename' command: Usage: rename "
                   "[old_name AS/TO/-> new_name]+."),
        ("regex", "Error in 'SearchOperator:regex': Usage: regex <field> "
                  "(=|!=) <regex>."),
        ("rex", "Error in 'SearchOperator:rex': Usage: regex [field=<field>] "
                "<regex>."),
        ("timechart", "Error in 'timechart' command: You must specify data "
                      "field(s) to chart."),
    ])
    def test_each_says_what_it_wanted(
        self, client: TestClient, command: str, text: str,
    ) -> None:
        """A search whose `| sort` had lost its field list looked as though it
        had worked."""
        body = client.post(
            SPLUNK, headers=SPLUNK_AUTH,
            data={"search": f"search index=sentinelone | {command}",
                  "output_mode": "json", "exec_mode": "oneshot"},
        ).json()

        assert body["messages"][0] == {"type": "FATAL", "text": text}

    @pytest.mark.parametrize("command", ["where", "stats", "fields", "head", "tail"])
    def test_the_ones_that_take_no_argument_still_run(
        self, client: TestClient, command: str,
    ) -> None:
        """splunkd accepts these bare — the other half of the measurement."""
        body = client.post(
            SPLUNK, headers=SPLUNK_AUTH,
            data={"search": f"search index=sentinelone | {command}",
                  "output_mode": "json", "exec_mode": "oneshot"},
        ).json()

        assert not [m for m in body.get("messages", []) if m["type"] == "FATAL"]


class TestNumbersOutsideTheRange:
    """Bounds a paginating client actually reaches."""

    ES = {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
    }

    def test_from_and_size_are_worded_differently(self, client: TestClient) -> None:
        """mockdr used one formula for both."""
        low_from = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={"from": -1},
        ).json()["error"]
        low_size = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={"size": -1},
        ).json()["error"]

        assert low_from["reason"] == "[from] parameter cannot be negative but was [-1]"
        assert low_size["reason"] == "[size] parameter cannot be negative, found [-1]"

    def test_terminate_after_takes_zero_and_refuses_below(
        self, client: TestClient,
    ) -> None:
        """Zero means no limit; below it mockdr answered nothing at all."""
        assert client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"terminate_after": 0},
        ).status_code == 200

        refused = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"terminate_after": -1},
        )
        assert refused.status_code == 400
        assert refused.json()["error"]["reason"] == "terminateAfter must be > 0"

    @pytest.mark.parametrize(("member", "spelled", "value", "comparison"), [
        ("size", "size", 0, "greater than 0"),
        ("shard_size", "shardSize", -1, "greater than 0"),
        ("min_doc_count", "minDocCount", -1, "greater than or equal to 0"),
        ("shard_min_doc_count", "shardMinDocCount", -1,
         "greater than or equal to 0"),
    ])
    def test_a_terms_bound_outside_its_range_is_refused(
        self, client: TestClient, member: str, spelled: str, value: int,
        comparison: str,
    ) -> None:
        """A `size` of zero produced every bucket, a negative one reversed them."""
        resp = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {"terms": {
                "field": "host.name", member: value}}}},
        )

        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["type"] == "x_content_parse_exception"
        assert error["reason"].endswith(f"[terms] failed to parse field [{member}]")
        # The cause spells it in camel case where the reason spells it in snake.
        assert error["caused_by"]["reason"] == (
            f"[{spelled}] must be {comparison}. Found [{value}] in [a]"
        )

    def test_the_position_points_at_the_value_not_the_name(
        self, client: TestClient,
    ) -> None:
        """And at the `size` inside the aggregation, not the one at the top."""
        reason = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"size": 0, "aggs": {"a": {"terms": {
                "field": "host.name", "size": 0}}}},
        ).json()["error"]["reason"]

        assert reason.startswith("[1:")
        column = int(reason.split(":")[1].split("]")[0])
        assert column > 40

    def test_a_negative_count_is_not_a_count_of_zero(
        self, client: TestClient,
    ) -> None:
        """splunkd reads it as an unsigned 64-bit integer and reports that as
        the page size; mockdr answered the `count=0` number for both."""
        negative = client.get(
            "/splunk/services/authorization/roles", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "count": -1},
        ).json()["paging"]
        zero = client.get(
            "/splunk/services/authorization/roles", headers=SPLUNK_AUTH,
            params={"output_mode": "json", "count": 0},
        ).json()["paging"]

        assert negative["perPage"] == 18446744073709552000
        assert zero["perPage"] == 10000000


class TestAMemberOfTheWrongType:
    """A scalar where the cluster wanted an object."""

    ES = {
        "Authorization": "Basic " + base64.b64encode(
            b"elastic:mock-elastic-password").decode(),
    }

    @pytest.mark.parametrize(("member", "value", "token"), [
        ("query", [], "START_ARRAY"),
        ("query", "x", "VALUE_STRING"),
        ("query", 1, "VALUE_NUMBER"),
        ("query", True, "VALUE_BOOLEAN"),
        ("query", False, "VALUE_BOOLEAN"),
        ("aggs", "x", "VALUE_STRING"),
        ("highlight", 1, "VALUE_NUMBER"),
        ("collapse", "x", "VALUE_STRING"),
        ("post_filter", [], "START_ARRAY"),
        ("fields", 1, "VALUE_NUMBER"),
    ])
    def test_it_reads_as_an_unknown_key(
        self, client: TestClient, member: str, value: object, token: str,
    ) -> None:
        """The parser looked for an object under that name and found something
        else — and `true` and `false` are both VALUE_BOOLEAN, where mockdr
        split them the way Jackson does."""
        resp = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={member: value},
        )

        assert resp.status_code == 400
        assert resp.json()["error"]["reason"] == (
            f"Unknown key for a {token} in [{member}]."
        )

    def test_the_members_with_a_shape_of_their_own(self, client: TestClient) -> None:
        """`_source` and `stored_fields` name the shapes they take, and where
        the parser stood; `explain` and `track_total_hits` name neither."""
        source = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={"_source": 1},
        ).json()["error"]
        stored = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"stored_fields": True},
        ).json()["error"]
        explain = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"explain": "please"},
        ).json()["error"]
        counted = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"track_total_hits": "yes"},
        ).json()["error"]

        assert source["reason"] == (
            "Expected one of [VALUE_BOOLEAN, VALUE_STRING, START_ARRAY, "
            "START_OBJECT] but found [VALUE_NUMBER]"
        )
        assert source["line"] == 1
        assert stored["reason"] == (
            "Expected [VALUE_STRING] or [START_ARRAY] in [stored_fields] "
            "but found [VALUE_BOOLEAN]"
        )
        assert explain["type"] == "illegal_argument_exception"
        assert explain["reason"] == (
            "Failed to parse value [please] as only [true] or [false] are allowed."
        )
        assert counted["type"] == "number_format_exception"
        assert "line" not in counted

    def test_a_sort_on_one_field_needs_no_array_around_it(
        self, client: TestClient,
    ) -> None:
        """It iterated the string and sorted on its letters."""
        assert client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"sort": "host.name", "size": 0},
        ).status_code == 200
        assert client.post(
            "/elastic/.siem-signals/_search", headers=self.ES,
            json={"sort": {"host.name": "desc"}, "size": 0},
        ).status_code == 200

    def test_a_scalar_sort_names_a_field_and_an_array_member_does_not(
        self, client: TestClient,
    ) -> None:
        """Two different complaints, and the second is flat rather than wrapped."""
        bare = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={"sort": 1},
        ).json()["error"]
        inside = client.post(
            "/elastic/.siem-signals/_search", headers=self.ES, json={"sort": [1]},
        ).json()["error"]

        assert bare["type"] == "search_phase_execution_exception"
        assert inside["type"] == "illegal_argument_exception"
        assert inside["reason"] == (
            "malformed sort format, within the sort array, an object, "
            "or an actual string are allowed"
        )

    def test_a_page_past_the_result_window_is_refused(
        self, client: TestClient,
    ) -> None:
        """Kibana relays the cluster's own failure; mockdr answered the page,
        so a client asking for more than the window got one here and a
        refusal in production."""
        resp = client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"per_page": 10001},
        )

        assert resp.status_code == 400
        message = resp.json()["message"]
        assert message.startswith("all shards failed: search_phase_execution_exception")
        assert "\n\tCaused by:\n\t\tillegal_argument_exception: " in message
        assert "\n\tRoot causes:\n\t\tillegal_argument_exception: " in message
        assert "but was [10001]" in message

    def test_it_is_from_plus_size_not_size_alone(self, client: TestClient) -> None:
        """The page number counts toward the window."""
        assert client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"page": 10, "per_page": 1000},
        ).status_code == 200
        assert client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"page": 11, "per_page": 1000},
        ).status_code == 400

    def test_the_schema_still_speaks_first(self, client: TestClient) -> None:
        """A page that is not a number is zod's complaint, not the window's."""
        resp = client.get(
            "/kibana/api/detection_engine/rules/_find", headers=ES_AUTH,
            params={"page": "abc", "per_page": 10001},
        )

        assert resp.status_code == 400
        assert "page: Expected number" in str(resp.json()["message"])


class TestOneKvCollectionByName:
    """splunkd serves a collection's configuration under its own path."""

    BASE = "/splunk/servicesNS/nobody/search/storage/collections/config"

    def test_the_collection_can_be_read_back(self, client: TestClient) -> None:
        """mockdr had only the listing, so reading one back met the
        catch-all's complaint about a missing target name."""
        listed = client.get(
            self.BASE, headers=SPLUNK_AUTH, params={"output_mode": "json"},
        ).json()["entry"]
        name = listed[0]["name"]

        one = client.get(
            f"{self.BASE}/{name}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )

        assert one.status_code == 200
        assert [e["name"] for e in one.json()["entry"]] == [name]
        assert one.json()["paging"]["total"] == 1

    def test_a_single_read_names_what_the_collection_accepts(
        self, client: TestClient,
    ) -> None:
        """And the listing does not — with the first non-empty `wildcard`
        block in this mock, for the two families a schema is written in."""
        listed = client.get(
            self.BASE, headers=SPLUNK_AUTH, params={"output_mode": "json"},
        ).json()["entry"][0]
        one = client.get(
            f"{self.BASE}/{listed['name']}", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        ).json()["entry"][0]

        assert "fields" not in listed
        assert one["fields"]["wildcard"] == ["accelerated_fields\\..*", "field\\..*"]
        assert "enforceTypes" in one["fields"]["optional"]

    def test_a_name_nothing_defines_is_a_refusal(self, client: TestClient) -> None:
        resp = client.get(
            f"{self.BASE}/no-such-collection", headers=SPLUNK_AUTH,
            params={"output_mode": "json"},
        )

        assert resp.status_code == 404
        assert resp.json()["messages"][0]["text"] == (
            "Could not find object id=no-such-collection"
        )
