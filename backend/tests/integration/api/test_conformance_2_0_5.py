"""What the thoroughness pass before 2.0.5 measured, transcribed.

Every expectation came from a running Splunk 10.4.2, Elasticsearch 8.15.0 or
Kibana 8.15.0 via the conformance harness, or from hostile-body probing of
every route. The harness reports zero status/value/type disagreements on
129 probes with these in place; this file keeps it there without the real
products running.
"""
import base64

import pytest
from fastapi.testclient import TestClient

SPL = {"Authorization": "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()}
ES = {"Authorization": "Basic " + base64.b64encode(b"elastic:mock-elastic-password").decode()}
KBN = {**ES, "kbn-xsrf": "true"}
HEC = {"Authorization": "Splunk 11111111-1111-1111-1111-111111111111"}
J = {"output_mode": "json"}


class TestSplunkNativeJsonTypes:
    """splunkd's JSON carries booleans and integers; 2.0.1's strings were an inference."""

    def _job(self, client: TestClient) -> dict:
        sid = client.post("/splunk/services/search/jobs", headers=SPL, params=J,
                          data={"search": "search index=main | head 1", "exec_mode": "blocking"}).json()["sid"]
        return client.get(f"/splunk/services/search/jobs/{sid}", headers=SPL, params=J).json()["entry"][0]["content"]

    def test_booleans_are_booleans(self, client: TestClient) -> None:
        content = self._job(client)
        for key in ("isDone", "isFailed", "isPaused", "isSaved"):
            assert isinstance(content[key], bool), key

    def test_counts_are_integers_and_done_progress_is_one(self, client: TestClient) -> None:
        content = self._job(client)
        for key in ("eventCount", "resultCount", "scanCount", "ttl"):
            assert type(content[key]) is int, key
        assert content["doneProgress"] == 1 and type(content["doneProgress"]) is int

    def test_the_job_list_agrees(self, client: TestClient) -> None:
        self._job(client)
        entry = client.get("/splunk/services/search/jobs", headers=SPL, params={**J, "count": 1}).json()["entry"][0]
        assert isinstance(entry["content"]["isDone"], bool)

    def test_index_counts_are_integers_but_db_size_is_a_string(self, client: TestClient) -> None:
        content = client.get("/splunk/services/data/indexes", headers=SPL, params={**J, "count": 1}).json()["entry"][0]["content"]
        assert type(content["totalEventCount"]) is int
        assert type(content["frozenTimePeriodInSecs"]) is int
        assert isinstance(content["currentDBSizeMB"], str)  # measured: the one string among integers


class TestSplunkRefusals:
    """Status codes and wording measured on 10.4.2."""

    def test_services_catalogue_does_not_exist(self, client: TestClient) -> None:
        assert client.get("/splunk/services", headers=SPL, params=J).status_code == 404

    def test_wrong_verb_is_400_not_405(self, client: TestClient) -> None:
        resp = client.delete("/splunk/services/server/info", headers=SPL, params=J)
        assert resp.status_code == 400
        assert resp.json()["messages"][0]["text"] == 'Cannot perform action "DELETE" without a target name to act on.'

    def test_create_without_a_name_uses_the_same_wording(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/data/indexes", headers=SPL, data={"output_mode": "json"})
        assert resp.status_code == 400
        assert resp.json()["messages"][0]["text"] == 'Cannot perform action "POST" without a target name to act on.'

    def test_login_without_a_password_is_400(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/auth/login", data={"username": "admin", "output_mode": "json"})
        assert resp.status_code == 400
        assert resp.json()["messages"][0] == {"type": "WARN", "text": "Login failed"}

    def test_kv_store_refusals_are_xml(self, client: TestClient) -> None:
        resp = client.get("/splunk/servicesNS/nobody/search/storage/collections/data/no_such_collection", headers=SPL)
        assert resp.status_code == 404
        assert resp.headers["content-type"].startswith("text/xml")
        assert "An object with name=no_such_collection does not exist" in resp.text

    def test_unknown_object_wording(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/data/indexes/no_such_index", headers=SPL, params=J)
        assert resp.json()["messages"][0]["text"] == "Could not find object id=no_such_index"

    def test_job_subresource_of_unknown_sid(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/search/jobs/0000000000.000000/results_preview", headers=SPL, params=J)
        assert resp.json()["messages"][0] == {"type": "FATAL", "text": "Unknown sid."}

    def test_export_accepts_post(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/search/jobs/export", headers=SPL, data={"output_mode": "json"})
        assert resp.status_code == 400  # a refusal for the missing search, not a 405
        assert resp.json()["messages"][0]["type"] == "FATAL"


class TestSplunkParserMeasuredClassification:
    """Pipelines, stream types and args per command, from the real parser."""

    URL = "/splunk/services/search/parser"

    def _commands(self, client: TestClient, q: str) -> dict:
        body = client.post(self.URL, headers=SPL, data={"q": q, "output_mode": "json"}).json()
        return {c["command"]: c for c in body["commands"]}

    @pytest.mark.parametrize(("cmd", "pipeline", "stream"), [
        ("sort -count", "events", "SP_EVENTS"),
        ("tail 3", "events", "SP_EVENTS"),
        ("dedup host", "stateful", "SP_STATEFUL"),
        ("top limit=5 host", "report", "SP_STREAMREPORT"),
        ("rare host", "report", "SP_STREAMREPORT"),
    ])
    def test_classification(self, client: TestClient, cmd: str, pipeline: str, stream: str) -> None:
        c = self._commands(client, f"search index=x | {cmd}")[cmd.split()[0]]
        assert (c["pipeline"], c["streamType"]) == (pipeline, stream)

    def test_top_args_shape(self, client: TestClient) -> None:
        args = self._commands(client, "search index=x | top limit=5 host")["top"]["args"]
        assert args == {"limit": 5, "showperc": True, "showcount": True,
                        "percentfield": "percent", "countfield": "count", "fields": ["host"]}

    def test_timechart_args_shape(self, client: TestClient) -> None:
        args = self._commands(client, "search index=x | timechart span=1h count by host")["timechart"]["args"]
        assert args["stat-specifiers"] == [{"function": "count", "rename": "count"}]
        assert (args["xfield"], args["xfieldopts"], args["seriesfield"]) == ("_time", ["span=1h"], "host")

    def test_sort_pre_streaming_op(self, client: TestClient) -> None:
        c = self._commands(client, "search index=x | sort -count")["sort"]
        assert (c["isStreamingOpRequired"], c["preStreamingOp"]) == (True, "presort 10000 -auto(count)")

    def test_generating_command_first(self, client: TestClient) -> None:
        body = client.post(self.URL, headers=SPL, data={"q": "| makeresults count=1 | head 1", "output_mode": "json"}).json()
        assert body["commands"][0]["command"] == "makeresults"
        assert body["commands"][0]["isGenerating"] is True
        assert body["eventsSearch"] == ""

    def test_pipe_inside_quotes_is_not_a_stage(self, client: TestClient) -> None:
        body = client.post(self.URL, headers=SPL, data={"q": 'search msg="a|b" | head 5', "output_mode": "json"}).json()
        assert body["eventsSearch"] == 'search msg="a|b"'

    def test_keywords_are_case_insensitive(self, client: TestClient) -> None:
        args = self._commands(client, "search index=x | stats dc(host) AS hosts BY a, b")["stats"]["args"]
        # An aggregation with an argument names its field (measured on 10.4.2).
        assert args["stat-specifiers"] == [{"function": "dc", "field": "host", "rename": "hosts"}]
        assert args["groupby-fields"] == ["a", "b"]


class TestHecMeasured:
    """Codes and batch semantics from a real collector."""

    def test_array_body_is_a_batch(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/collector", headers=HEC, json=[{"event": "a"}, {"event": "b"}])
        assert resp.status_code == 200 and resp.json()["code"] == 0

    def test_non_numeric_time_is_code_15(self, client: TestClient) -> None:
        body = client.post("/splunk/services/collector", headers=HEC, json={"event": "p", "time": "yesterday"}).json()
        assert (body["code"], body["text"], body["invalid-event-number"]) == (15, "Error in handling indexed fields", 0)

    def test_blank_event_is_reported_before_later_broken_json(self, client: TestClient) -> None:
        """HEC streams: position 0 is rejected before position 1 is parsed."""
        body = client.post("/splunk/services/collector", headers=HEC, content='{"event":""}{not json').json()
        assert (body["code"], body["invalid-event-number"]) == (13, 0)

    def test_ack_without_acknowledgement_is_code_14(self, client: TestClient) -> None:
        body = client.post("/splunk/services/collector/ack", headers=HEC, json={"acks": [0]}).json()
        assert body == {"text": "ACK is disabled", "code": 14}

    def test_get_on_the_collector(self, client: TestClient) -> None:
        resp = client.get("/splunk/services/collector", headers=HEC)
        assert resp.status_code == 405
        assert resp.json() == {"text": "The requested URL was not found on this server.", "code": 404}

    def test_deeply_nested_json_is_code_6_not_a_500(self, client: TestClient) -> None:
        resp = client.post("/splunk/services/collector", headers=HEC, content='{"q":' * 20000 + "1" + "}" * 20000)
        assert resp.status_code == 400 and resp.json()["code"] == 6


class TestElasticsearchMeasured:
    """Exception types and root routes from 8.15.0."""

    def test_count_mget_bulk_exist_at_the_root(self, client: TestClient) -> None:
        assert client.post("/elastic/_count", headers=ES, json={}).status_code == 200
        assert client.post("/elastic/_mget", headers=ES, json={"ids": ["x"]}).status_code == 200
        assert client.post("/elastic/_bulk", headers=ES, content=b"").status_code == 400

    def test_mget_on_a_missing_index_is_200_with_the_error_per_doc(self, client: TestClient) -> None:
        resp = client.post("/elastic/no-such-index/_mget", headers=ES, json={"ids": ["1"]})
        assert resp.status_code == 200
        assert resp.json()["docs"][0]["error"]["type"] == "index_not_found_exception"

    @pytest.mark.parametrize(("body", "es_type", "reason"), [
        ({"size": -1}, "illegal_argument_exception", "[size] parameter cannot be negative, found [-1]"),
        ({"size": "lots"}, "number_format_exception", 'For input string: "lots"'),
        ({"a": {"b": 1}}, "parsing_exception", "Unknown key for a START_OBJECT in [a]."),
    ])
    def test_exception_types(self, client: TestClient, body: dict, es_type: str, reason: str) -> None:
        error = client.post("/elastic/_search", headers=ES, json=body).json()["error"]
        assert (error["type"], error["reason"]) == (es_type, reason)

    def test_result_window_is_a_search_phase_failure(self, client: TestClient) -> None:
        error = client.post("/elastic/_search", headers=ES, json={"from": 20000, "size": 10}).json()["error"]
        assert (error["type"], error["reason"], error["phase"]) == ("search_phase_execution_exception", "all shards failed", "query")
        assert error["root_cause"][0]["type"] == "illegal_argument_exception"
        assert error["caused_by"]["caused_by"]["reason"].startswith("Result window is too large")

    def test_array_body(self, client: TestClient) -> None:
        error = client.post("/elastic/_search", headers={**ES, "Content-Type": "application/json"}, content=b"[1,2,3]").json()["error"]
        assert (error["type"], error["reason"], error["line"], error["col"]) == ("parsing_exception", "Expected [START_OBJECT] but found [START_ARRAY]", 1, 1)

    def test_unknown_aggregation_type_carries_caused_by(self, client: TestClient) -> None:
        error = client.post("/elastic/_search", headers=ES, json={"size": 0, "aggs": {"a": {"not_an_agg": {"field": "x"}}}}).json()["error"]
        assert error["reason"] == "Unknown aggregation type [not_an_agg]"
        assert error["caused_by"]["type"] == "named_object_not_found_exception"

    def test_source_parameter(self, client: TestClient) -> None:
        resp = client.get("/elastic/_search", headers=ES, params={"source": '{"query":{"bogus":{}}}', "source_content_type": "application/json"})
        assert resp.status_code == 400 and resp.json()["error"]["reason"] == "unknown query [bogus]"

    def test_single_unknown_segment_is_an_index_name(self, client: TestClient) -> None:
        bad = client.get("/elastic/_no_such_endpoint", headers=ES)
        assert bad.status_code == 400 and bad.json()["error"]["type"] == "invalid_index_name_exception"
        missing = client.get("/elastic/no_such_plain_path", headers=ES)
        assert missing.status_code == 404 and missing.json()["error"]["type"] == "index_not_found_exception"

    def test_unknown_cat_verb(self, client: TestClient) -> None:
        resp = client.get("/elastic/_cat/no_such_thing", headers=ES)
        assert resp.status_code == 405 and isinstance(resp.json()["error"], str)

    def test_wrong_password_names_the_user(self, client: TestClient) -> None:
        resp = client.get("/elastic/_cluster/health", headers={"Authorization": "Basic " + base64.b64encode(b"elastic:wrong").decode()})
        assert "unable to authenticate user [elastic] for REST request" in resp.json()["error"]["reason"]

    def test_bulk_malformed_action_line(self, client: TestClient) -> None:
        resp = client.post("/elastic/_bulk", headers=ES, content=b'{"a":null}\n')
        assert resp.status_code == 400
        assert resp.json()["error"]["reason"] == ("Malformed action/metadata line [1], expected field [create], [delete], [index] or [update] but found [a]")


class TestKibanaMeasured:
    """Refusals in Kibana 8.15's words."""

    def test_rule_with_unknown_type(self, client: TestClient) -> None:
        resp = client.post("/kibana/api/detection_engine/rules", headers=KBN,
                           json={"name": "c", "description": "d", "type": "not_a_type", "severity": "low", "risk_score": 1})
        assert resp.status_code == 400
        assert resp.json()["message"].startswith("[request body]: type: Invalid discriminator value. Expected 'eql' | 'query'")

    def test_rule_lookup_needs_an_id_and_the_message_is_a_list(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/detection_engine/rules", headers=ES)
        assert resp.status_code == 400
        assert resp.json() == {"message": ['either "id" or "rule_id" must be set'], "status_code": 400}

    def test_delete_by_rule_id(self, client: TestClient) -> None:
        resp = client.delete("/kibana/api/detection_engine/rules", headers=KBN, params={"rule_id": "no-such"})
        assert resp.status_code == 404 and resp.json()["message"] == 'rule_id: "no-such" not found'

    def test_case_missing_fields_io_ts(self, client: TestClient) -> None:
        resp = client.post("/kibana/api/cases", headers=KBN, json={"title": "conformance"})
        assert resp.status_code == 400
        assert resp.json()["message"] == ",".join(f'Invalid value "undefined" supplied to "{f}"' for f in ("description", "tags", "connector", "settings", "owner"))

    def test_case_garbage_body_is_refused_not_created(self, client: TestClient) -> None:
        assert client.post("/kibana/api/cases", headers=KBN, json={"a": {"b": 1}}).status_code == 400

    def test_case_find_bad_status(self, client: TestClient) -> None:
        resp = client.get("/kibana/api/cases/_find", headers=ES, params={"status": "exploded"})
        assert resp.status_code == 400 and resp.json()["message"] == 'Invalid value "exploded" supplied to "status"'

    def test_endpoint_action_without_ids(self, client: TestClient) -> None:
        resp = client.post("/kibana/api/endpoint/action/isolate", headers=KBN, json={})
        assert resp.json()["message"] == "[request body.endpoint_ids]: expected value of type [array] but got [undefined]"

    def test_signals_search_empty(self, client: TestClient) -> None:
        resp = client.post("/kibana/api/detection_engine/signals/search", headers=KBN, json={})
        assert resp.json() == {"message": '"value" must have at least 1 children', "status_code": 400}

    def test_per_page_zero_is_accepted(self, client: TestClient) -> None:
        assert client.get("/kibana/api/detection_engine/rules/_find", headers=ES, params={"per_page": 0}).status_code == 200

    def test_features_shape(self, client: TestClient) -> None:
        features = client.get("/kibana/api/features", headers=ES).json()
        siem = next(f for f in features if f["id"] == "siem")
        assert {"order", "catalogue", "management", "alerting", "subFeatures", "privileges"} <= set(siem)
        assert {"api", "ui", "savedObject", "app", "catalogue"} <= set(siem["privileges"]["all"])
        assert any(f["privileges"] is None for f in features)


class TestNoRouteAnswers500ToAMalformedBody:
    """The 31 crash paths hostile probing found, by family."""

    @pytest.mark.parametrize(("method", "path", "headers", "content"), [
        ("POST", "/cs/devices/entities/devices/v2", None, '{"ids":null}'),
        ("POST", "/xdr/public_api/v1/endpoints/get_policy/", {"x-xdr-auth-id": "1", "Authorization": "xdr-admin-secret"}, "{}"),
        ("POST", "/splunk/servicesNS/x/x/storage/collections/config", SPL, "null"),
        ("POST", "/web/api/v2.1/remote-scripts/execute", {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}, "{}"),
    ])
    def test_family(self, client: TestClient, method: str, path: str, headers: dict | None, content: str) -> None:
        if headers is None:
            token = client.post("/cs/oauth2/token", data={"client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret"}).json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
        resp = client.request(method, path, headers={**headers, "Content-Type": "application/json"}, content=content)
        assert resp.status_code == 400, resp.text
        # The point is "a vendor-shaped refusal": JSON, or Atom XML where splunkd
        # answers XML without output_mode — never a plain-text 500.
        assert not resp.headers["content-type"].startswith("text/plain")

    def test_kql_bare_pipe_is_a_400(self, client: TestClient) -> None:
        token = client.post("/mde/oauth2/v2.0/token", data={"grant_type": "client_credentials", "client_id": "mde-mock-admin-client", "client_secret": "mde-mock-admin-secret", "scope": "x"}).json()["access_token"]
        resp = client.post("/mde/api/advancedqueries/run", headers={"Authorization": f"Bearer {token}"}, json={"Query": "|"})
        assert resp.status_code == 400
