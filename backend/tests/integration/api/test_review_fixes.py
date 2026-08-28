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
            "/elastic/sentinelone/_search", headers=self.ES, params={"zzz": "1"},
        )

        assert "/elastic" not in resp.json()["error"]["reason"]
        assert "[/sentinelone/_search]" in resp.json()["error"]["reason"]

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
