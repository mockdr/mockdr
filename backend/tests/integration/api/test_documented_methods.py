"""The methods the 2.1 swagger documents on paths this mock already served.

`scripts/param_drift.py` compared the parameters of operations both sides
describe, and could not see an operation only one side has: six documented
calls landed on a path mockdr serves with other verbs and were answered 405.
Five of them are how a real client writes — SentinelOne updates an exclusion
and a blocklist entry by body, not by a path of its own, and deletes rules
and tags by filter — so a SOAR integration doing the ordinary thing got a
405 from a route that was, on paper, implemented.

Each case here is the swagger's own contract: what `data` must carry, what a
missing member does, and what the answer looks like.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _first(client: TestClient, headers: dict, path: str) -> dict:
    body = client.get(f"{BASE}{path}", headers=headers).json()
    assert body["data"], f"nothing seeded at {path}"
    return dict(body["data"][0])


class TestExclusionsAreUpdatedByBody:
    """`PUT /exclusions`: `data.id` names the record, and the reply is a list."""

    def test_the_change_is_kept(self, client: TestClient, auth_headers: dict) -> None:
        existing = _first(client, auth_headers, "/exclusions")
        resp = client.put(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"data": {
                "id": existing["id"],
                "osType": existing["osType"],
                "type": existing["type"],
                "description": "changed by the documented call",
            }},
        )
        assert resp.status_code == 200
        # exclusions.schemas_ExclusionSchema_many_200 — a list, not a single.
        assert resp.json()["data"][0]["description"] == "changed by the documented call"

        after = client.get(
            f"{BASE}/exclusions", headers=auth_headers, params={"ids": existing["id"]},
        ).json()["data"][0]
        assert after["description"] == "changed by the documented call"

    def test_an_id_nobody_has_is_a_404(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"data": {"id": "1", "osType": "windows", "type": "path"}},
        )
        assert resp.status_code == 404

    def test_a_body_missing_a_required_member_is_a_400(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """The swagger requires `id`, `osType` and `type` inside `data`."""
        resp = client.put(
            f"{BASE}/exclusions",
            headers=auth_headers,
            json={"data": {"osType": "windows", "type": "path"}},
        )
        assert resp.status_code == 400


class TestRestrictionsAreUpdatedByBody:
    """`PUT /restrictions`, the same contract over the hash blocklist."""

    def test_the_change_is_kept(self, client: TestClient, auth_headers: dict) -> None:
        existing = _first(client, auth_headers, "/restrictions")
        resp = client.put(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={"data": {
                "id": existing["id"],
                "osType": existing["osType"],
                "type": existing["type"],
                "description": "blocked for a stated reason",
            }},
        )
        assert resp.status_code == 200
        assert resp.json()["data"][0]["description"] == "blocked for a stated reason"

        after = client.get(f"{BASE}/restrictions", headers=auth_headers).json()["data"]
        changed = [r for r in after if r["id"] == existing["id"]][0]
        assert changed["description"] == "blocked for a stated reason"

    def test_an_id_nobody_has_is_a_404(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/restrictions",
            headers=auth_headers,
            json={"data": {"id": "1", "osType": "windows", "type": "black_hash"}},
        )
        assert resp.status_code == 404


class TestRulesAreDeletedByFilter:
    """`DELETE /cloud-detection/rules`: the body describes which rules."""

    def test_only_the_described_rules_go(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        rules = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        severity = rules[0]["severity"]
        doomed = [r for r in rules if r["severity"] == severity]

        resp = client.request(
            "DELETE", f"{BASE}/cloud-detection/rules",
            headers=auth_headers, json={"filter": {"severities": [severity]}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == len(doomed)

        left = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        assert len(left) == len(rules) - len(doomed)
        assert all(r["severity"] != severity for r in left)

    def test_an_empty_filter_deletes_nothing(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """An empty filter describes every rule there is — refused, not obeyed."""
        before = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        resp = client.request(
            "DELETE", f"{BASE}/cloud-detection/rules", headers=auth_headers, json={"filter": {}},
        )
        assert resp.status_code == 400
        after = client.get(f"{BASE}/cloud-detection/rules", headers=auth_headers).json()["data"]
        assert len(after) == len(before)

    def test_a_filter_this_install_cannot_answer_is_refused(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """Deleting a wider set than the one asked for is the failure to avoid."""
        resp = client.request(
            "DELETE", f"{BASE}/cloud-detection/rules",
            headers=auth_headers, json={"filter": {"reachedLimit": True}},
        )
        assert resp.status_code == 400


class TestTagsAreDeletedByFilter:
    """`DELETE /tag-manager`: by id, by free text, or by scope."""

    @staticmethod
    def _tags(client: TestClient, headers: dict) -> list[dict]:
        created = client.post(
            f"{BASE}/tag-manager", headers=headers,
            json={"data": {
                "key": "Retire", "value": "Now", "type": "agents",
                "description": "for the delete test",
            }},
        )
        assert created.status_code == 200
        return [created.json()["data"]]

    def test_a_named_tag_goes(self, client: TestClient, auth_headers: dict) -> None:
        tag = self._tags(client, auth_headers)[0]
        resp = client.request(
            "DELETE", f"{BASE}/tag-manager",
            headers=auth_headers, json={"filter": {"tagIds": [tag["id"]]}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_free_text_selects_by_key_value_and_description(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        self._tags(client, auth_headers)
        resp = client.request(
            "DELETE", f"{BASE}/tag-manager",
            headers=auth_headers, json={"filter": {"query": "for the delete test"}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_an_empty_filter_deletes_nothing(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.request(
            "DELETE", f"{BASE}/tag-manager", headers=auth_headers, json={"filter": {}},
        )
        assert resp.status_code == 400


class TestTheAccountPolicyIsSetWhereItIsRead:
    """`PUT /accounts/{id}/policy`, beside the GET that was already there."""

    def test_the_change_is_answered_back(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        account = client.get(f"{BASE}/accounts", headers=auth_headers).json()["data"][0]["id"]
        resp = client.put(
            f"{BASE}/accounts/{account}/policy",
            headers=auth_headers, json={"data": {"mitigationMode": "protect"}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["mitigationMode"] == "protect"

    def test_an_account_nobody_has_is_a_404(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        """As on the GET: confirming a change against an account that does
        not exist is the worst way to say no."""
        resp = client.put(
            f"{BASE}/accounts/999999999999999999/policy",
            headers=auth_headers, json={"data": {"mitigationMode": "protect"}},
        )
        assert resp.status_code == 404


class TestTheConsoleConfigurationIsSettable:
    """`PUT /system/configuration`, whose GET answered blanks nothing could set."""

    def test_a_setting_survives_to_the_next_read(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=auth_headers,
            json={
                "data": {"advancedMode": True, "accessibleUrl": "https://console.acmecorp"},
                "filter": {"tenant": True},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["advancedMode"] is True

        after = client.get(f"{BASE}/system/configuration", headers=auth_headers).json()["data"]
        assert after["advancedMode"] is True
        assert after["accessibleUrl"] == "https://console.acmecorp"

    def test_the_scope_is_required(self, client: TestClient, auth_headers: dict) -> None:
        """The swagger requires `data` and `filter` both: a change with no
        scope is a malformed request, not a change applied everywhere."""
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=auth_headers, json={"data": {"advancedMode": True}},
        )
        assert resp.status_code == 400

    def test_a_setting_this_console_does_not_have_is_refused(
        self, client: TestClient, auth_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=auth_headers,
            json={"data": {"logLevel": "debug"}, "filter": {"tenant": True}},
        )
        assert resp.status_code == 400

    def test_a_read_only_caller_cannot_set_it(
        self, client: TestClient, viewer_headers: dict,
    ) -> None:
        resp = client.put(
            f"{BASE}/system/configuration",
            headers=viewer_headers,
            json={"data": {"advancedMode": True}, "filter": {"tenant": True}},
        )
        assert resp.status_code == 403


class TestAMachineIsChangedWhereItIsRead:
    """`PATCH /api/machines/{id}`, the MDE call beside the GET and the actions.

    The same sweep over the Defender documentation found one method answered
    405 on a path this mock already serves: the one that changes the machine
    itself. MDE documents `machineTags` and `deviceValue` on it and answers
    the updated machine back.
    """

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def _machine(self, client: TestClient, headers: dict) -> str:
        return str(client.get("/mde/api/machines", headers=headers).json()["value"][0]["id"])

    def test_the_change_is_there_on_the_next_read(self, client: TestClient) -> None:
        headers = self._auth(client)
        machine = self._machine(client, headers)
        resp = client.patch(
            f"/mde/api/machines/{machine}",
            headers=headers,
            json={"machineTags": ["crown-jewel"], "deviceValue": "High"},
        )
        assert resp.status_code == 200
        assert resp.json()["machineTags"] == ["crown-jewel"]
        assert resp.json()["deviceValue"] == "High"

        after = client.get(f"/mde/api/machines/{machine}", headers=headers).json()
        assert after["machineTags"] == ["crown-jewel"]
        assert after["deviceValue"] == "High"

    def test_a_device_value_mde_does_not_have_is_refused(
        self, client: TestClient,
    ) -> None:
        headers = self._auth(client)
        machine = self._machine(client, headers)
        resp = client.patch(
            f"/mde/api/machines/{machine}", headers=headers, json={"deviceValue": "Critical"},
        )
        assert resp.status_code == 400

    def test_tags_have_to_be_a_list(self, client: TestClient) -> None:
        headers = self._auth(client)
        machine = self._machine(client, headers)
        resp = client.patch(
            f"/mde/api/machines/{machine}", headers=headers, json={"machineTags": "one"},
        )
        assert resp.status_code == 400

    def test_a_machine_nobody_has_is_a_404(self, client: TestClient) -> None:
        headers = self._auth(client)
        resp = client.patch(
            "/mde/api/machines/00000000-0000-0000-0000-000000000000",
            headers=headers, json={"deviceValue": "Low"},
        )
        assert resp.status_code == 404


class TestCortexNamesItsTargetsTheWayCortexDoes:
    """The endpoint action routes take a `filters` block, not an id.

    `scripts/schema_drift.py` recorded eight Cortex routes as "skipped: HTTP
    500" and still printed `0 drift findings`, so the audit's own summary hid
    them. Three of those routes — `file_retrieval`, `quarantine` and `scan` —
    have no `endpoint_id` in the body Cortex documents at all, and the
    handlers read nothing else: every well-formed call answered
    `500 XDR internal server error / Endpoint  not found`. `isolate` and
    `unisolate` document both spellings and accepted only one.
    """

    @staticmethod
    def _auth() -> dict:
        import hashlib
        import secrets
        import time

        nonce = secrets.token_hex(32)
        stamp = str(int(time.time() * 1000))
        digest = hashlib.sha256(("xdr-admin-secret" + nonce + stamp).encode()).hexdigest()
        return {
            "x-xdr-auth-id": "1", "x-xdr-nonce": nonce,
            "x-xdr-timestamp": stamp, "Authorization": digest,
        }

    def _endpoints(self, client: TestClient) -> list[str]:
        reply = client.post(
            "/xdr/public_api/v1/endpoints/get_endpoint/", headers=self._auth(),
            json={"request_data": {}},
        ).json()["reply"]
        return [e["endpoint_id"] for e in reply["endpoints"]]

    @staticmethod
    def _filters(ids: list[str]) -> list[dict]:
        return [{"field": "endpoint_id_list", "operator": "in", "value": ids}]

    def test_file_retrieval_takes_the_documented_body(
        self, client: TestClient,
    ) -> None:
        endpoint = self._endpoints(client)[0]
        resp = client.post(
            "/xdr/public_api/v1/endpoints/file_retrieval/", headers=self._auth(),
            json={"request_data": {
                "files": {"windows": ["C:\\temp\\evidence.txt"]},
                "filters": self._filters([endpoint]),
            }},
        )
        assert resp.status_code == 200
        assert resp.json()["reply"]["action_id"]

    def test_quarantine_takes_the_documented_body(self, client: TestClient) -> None:
        endpoint = self._endpoints(client)[0]
        resp = client.post(
            "/xdr/public_api/v1/endpoints/quarantine/", headers=self._auth(),
            json={"request_data": {
                "file_path": "/tmp/malware", "file_hash": "a" * 64,
                "filters": self._filters([endpoint]),
            }},
        )
        assert resp.status_code == 200

    def test_isolate_takes_either_spelling(self, client: TestClient) -> None:
        endpoint = self._endpoints(client)[0]
        by_id = client.post(
            "/xdr/public_api/v1/endpoints/isolate", headers=self._auth(),
            json={"request_data": {"endpoint_id": endpoint}},
        )
        by_filter = client.post(
            "/xdr/public_api/v1/endpoints/isolate", headers=self._auth(),
            json={"request_data": {"filters": self._filters([endpoint])}},
        )
        assert by_id.status_code == 200
        assert by_filter.status_code == 200

    def test_an_action_covers_every_endpoint_the_filter_selected(
        self, client: TestClient,
    ) -> None:
        """`get_action_status` keys its answer by endpoint, and a playbook
        waits for *its* endpoint to appear there."""
        first, second = self._endpoints(client)[:2]
        scan = client.post(
            "/xdr/public_api/v1/endpoints/scan/", headers=self._auth(),
            json={"request_data": {"filters": self._filters([first, second])}},
        ).json()["reply"]
        assert scan["endpoints_count"] == "2"

        status = client.post(
            "/xdr/public_api/v1/actions/get_action_status/", headers=self._auth(),
            json={"request_data": {"group_action_id": scan["action_id"]}},
        ).json()["reply"]
        assert set(status["data"]) == {first, second}

    def test_a_request_naming_nobody_is_still_refused(
        self, client: TestClient,
    ) -> None:
        resp = client.post(
            "/xdr/public_api/v1/endpoints/isolate", headers=self._auth(),
            json={"request_data": {}},
        )
        assert resp.status_code == 500
        assert resp.json()["reply"]["err_code"] == 500


class TestRunningAScriptAndCollectingIt:
    """Start a script, poll it, read the result — the whole pattern.

    `run_script` read `endpoint_id_list` where Cortex requires `filters`, so
    a documented call selected nobody, created no action record, and still
    answered an `action_id`. Polling that id answered
    `500 Action … not found`, so the loop a playbook runs never closed. When
    it did resolve, the status was a tally of zeros — a client waiting for
    `endpoints_completed_successfully` to reach its endpoint count waited for
    ever — and the result was one canned row for an endpoint called
    `xdr-endpoint`.
    """

    @staticmethod
    def _auth() -> dict:
        import hashlib
        import secrets
        import time

        nonce = secrets.token_hex(32)
        stamp = str(int(time.time() * 1000))
        digest = hashlib.sha256(("xdr-admin-secret" + nonce + stamp).encode()).hexdigest()
        return {
            "x-xdr-auth-id": "1", "x-xdr-nonce": nonce,
            "x-xdr-timestamp": stamp, "Authorization": digest,
        }

    def _post(self, client: TestClient, path: str, request: dict) -> dict:
        return dict(client.post(
            f"/xdr/public_api/v1{path}", headers=self._auth(),
            json={"request_data": request},
        ).json())

    def _run(self, client: TestClient) -> tuple[dict, list[str]]:
        endpoints = [
            e["endpoint_id"] for e in
            self._post(client, "/endpoints/get_endpoint/", {})["reply"]["endpoints"][:2]
        ]
        script = self._post(client, "/scripts/get_scripts/", {})["reply"]["scripts"][0]
        run = self._post(client, "/scripts/run_script/", {
            "script_uid": script["script_uid"], "timeout": 600,
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoints}],
        })["reply"]
        return run, endpoints

    def test_the_run_answers_an_action_that_exists(self, client: TestClient) -> None:
        run, endpoints = self._run(client)
        assert run["endpoints_count"] == str(len(endpoints))
        status = self._post(
            client, "/scripts/get_script_execution_status/", {"action_id": run["action_id"]},
        )
        assert "err_code" not in status["reply"]

    def test_the_status_counts_the_endpoints_it_ran_on(self, client: TestClient) -> None:
        run, endpoints = self._run(client)
        status = self._post(
            client, "/scripts/get_script_execution_status/", {"action_id": run["action_id"]},
        )["reply"]
        assert status["endpoints_completed_successfully"] == len(endpoints)
        assert status["general_status"] == "COMPLETED_SUCCESSFULLY"

    def test_the_results_name_the_endpoints_it_ran_on(self, client: TestClient) -> None:
        run, endpoints = self._run(client)
        results = self._post(
            client, "/scripts/get_script_execution_results", {"action_id": run["action_id"]},
        )["reply"]
        assert results["script_name"]
        assert [row["endpoint_id"] for row in results["results"]] == endpoints
        # Cortex names these `execution_status` and `standard_output`.
        assert results["results"][0]["execution_status"] == "COMPLETED_SUCCESSFULLY"
        assert results["results"][0]["endpoint_name"]

    def test_terminate_process_takes_the_target_its_siblings_take(
        self, client: TestClient,
    ) -> None:
        endpoint = self._post(
            client, "/endpoints/get_endpoint/", {},
        )["reply"]["endpoints"][0]["endpoint_id"]
        by_agent = self._post(
            client, "/endpoints/terminate_process/",
            {"agent_id": endpoint, "process_id": 4242},
        )["reply"]
        assert by_agent["group_action_id"] == by_agent["action_id"]

        by_filter = self._post(
            client, "/endpoints/terminate_process/",
            {"process_id": 4242,
             "filters": [{"field": "endpoint_id_list", "operator": "in",
                          "value": [endpoint]}]},
        )["reply"]
        assert by_filter["action_id"]

    def test_retrieval_details_take_the_id_the_retrieval_answered(
        self, client: TestClient,
    ) -> None:
        endpoint = self._post(
            client, "/endpoints/get_endpoint/", {},
        )["reply"]["endpoints"][0]["endpoint_id"]
        retrieval = self._post(client, "/endpoints/file_retrieval/", {
            "files": {"windows": ["C:\\temp\\x.txt"]},
            "filters": [{"field": "endpoint_id_list", "operator": "in", "value": [endpoint]}],
        })["reply"]
        for spelling in ("action_id", "group_action_id"):
            details = self._post(
                client, "/actions/file_retrieval_details/",
                {spelling: retrieval["action_id"]},
            )
            assert "err_code" not in details["reply"], spelling


class TestFalconPublishesHiddenHostsTwice:
    """Falcon publishes every collection twice: ids, then documents.

    `hide_host` takes a host out of the listings, and the pair that shows
    what is hidden is `/devices/queries/devices-hidden/v1` (the ids) and
    `/devices/combined/devices-hidden/v1` (the documents). Only the second
    was served, so a client following the ids-then-entities pattern — which
    is how Falcon's own SDK reads a collection — met a 404 on the half it
    starts with.
    """

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_the_ids_route_answers_what_the_documents_route_lists(
        self, client: TestClient,
    ) -> None:
        cs = self._auth(client)
        devices = client.get(
            "/cs/devices/queries/devices/v1", headers=cs, params={"limit": 2},
        ).json()["resources"]
        client.post(
            "/cs/devices/entities/devices-actions/v2", headers=cs,
            params={"action_name": "hide_host"}, json={"ids": devices},
        )

        ids = client.get("/cs/devices/queries/devices-hidden/v1", headers=cs)
        assert ids.status_code == 200
        assert sorted(ids.json()["resources"]) == sorted(devices)
        assert ids.json()["meta"]["pagination"]["total"] == len(devices)

        documents = client.get(
            "/cs/devices/combined/devices-hidden/v1", headers=cs,
        ).json()["resources"]
        assert sorted(d["device_id"] for d in documents) == sorted(devices)

    def test_unhiding_empties_it_again(self, client: TestClient) -> None:
        cs = self._auth(client)
        devices = client.get(
            "/cs/devices/queries/devices/v1", headers=cs, params={"limit": 1},
        ).json()["resources"]
        for action in ("hide_host", "unhide_host"):
            client.post(
                "/cs/devices/entities/devices-actions/v2", headers=cs,
                params={"action_name": action}, json={"ids": devices},
            )
        assert client.get(
            "/cs/devices/queries/devices-hidden/v1", headers=cs,
        ).json()["resources"] == []


class TestAProcessIsWhatFalconDeclares:
    """`ProcessesapiProcessDetail` declares ten members, and no others.

    mockdr answered five beside them — `sha256`, `md5`, `user_name`,
    `user_sid`, `parent_process_id` — none of which Falcon's model carries
    on this route, so a client built against the mock's process would break
    against the real product. It also generated a process for *any* id,
    including one naming a device this tenant does not have.
    """

    DECLARED = {
        "process_id", "device_id", "command_line", "file_name",
        "process_id_local", "start_timestamp", "stop_timestamp",
    }

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/cs/oauth2/token", data={
            "client_id": "cs-mock-admin-client", "client_secret": "cs-mock-admin-secret",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_a_process_carries_only_declared_members(self, client: TestClient) -> None:
        cs = self._auth(client)
        device = client.get(
            "/cs/devices/queries/devices/v1", headers=cs, params={"limit": 1},
        ).json()["resources"][0]
        process = client.get(
            "/cs/processes/entities/processes/v1", headers=cs,
            params={"ids": f"pid:{device}:1"},
        ).json()["resources"][0]
        assert set(process) <= self.DECLARED
        assert process["device_id"] == device

    def test_a_device_this_tenant_lacks_has_no_processes(
        self, client: TestClient,
    ) -> None:
        answer = client.get(
            "/cs/processes/entities/processes/v1", headers=self._auth(client),
            params={"ids": "pid:no-such-device:1"},
        )
        assert answer.status_code == 200
        assert answer.json()["resources"] == []

    def test_processes_are_not_all_dated_the_same_instant(
        self, client: TestClient,
    ) -> None:
        cs = self._auth(client)
        devices = client.get(
            "/cs/devices/queries/devices/v1", headers=cs, params={"limit": 3},
        ).json()["resources"]
        starts = {
            client.get(
                "/cs/processes/entities/processes/v1", headers=cs,
                params={"ids": f"pid:{d}:1"},
            ).json()["resources"][0]["start_timestamp"]
            for d in devices
        }
        assert len(starts) == len(devices)


class TestDefenderCollectionsCanBeAddressed:
    """A listing that gives no id is a collection nothing can be read from.

    `mde_software` and `mde_vulnerabilities` are keyed `softwareId` and
    `vulnerabilityId` in the store and `id` on the wire, and the rename never
    happened: all 44 software entries and all 15 vulnerabilities answered
    `id: ""`. `GET /api/software/{id}` was unreachable for a client that had
    just listed them, which is the only way it learns an id — and the drift
    audit could not compare those four routes for the same reason.
    """

    @staticmethod
    def _auth(client: TestClient) -> dict:
        token = client.post("/mde/oauth2/v2.0/token", data={
            "client_id": "mde-mock-admin-client",
            "client_secret": "mde-mock-admin-secret",
            "grant_type": "client_credentials",
            "scope": "https://api.securitycenter.microsoft.com/.default",
        }).json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    @pytest.mark.parametrize("collection", ["software", "vulnerabilities"])
    def test_every_entry_can_be_read_by_the_id_it_reports(
        self, client: TestClient, collection: str,
    ) -> None:
        headers = self._auth(client)
        listing = client.get(f"/mde/api/{collection}", headers=headers).json()["value"]
        assert listing
        assert all(entry["id"] for entry in listing)

        first = listing[0]["id"]
        assert client.get(
            f"/mde/api/{collection}/{first}", headers=headers,
        ).status_code == 200
        references = client.get(
            f"/mde/api/{collection}/{first}/machineReferences", headers=headers,
        )
        assert references.status_code == 200
        assert references.json()["value"]

    @pytest.mark.parametrize("collection", ["software", "vulnerabilities"])
    def test_the_stored_key_is_not_answered_beside_it(
        self, client: TestClient, collection: str,
    ) -> None:
        entry = client.get(
            f"/mde/api/{collection}", headers=self._auth(client),
        ).json()["value"][0]
        assert "softwareId" not in entry
        assert "vulnerabilityId" not in entry

    def test_a_created_indicator_has_the_shape_a_listed_one_has(
        self, client: TestClient,
    ) -> None:
        """The create answer used to carry four members fewer than the very
        same record does when it is listed."""
        headers = self._auth(client)
        created = client.post("/mde/api/indicators", headers=headers, json={
            "indicatorValue": "shape.example.test", "indicatorType": "DomainName",
            "action": "Alert", "title": "shape probe",
        }).json()
        listed = client.get("/mde/api/indicators", headers=headers).json()["value"][0]
        assert set(created) == set(listed)
