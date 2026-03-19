"""Integration tests for all agent bulk-action paths.

Covers every branch of application/agents/commands.py:
- Every named action
- _resolve_ids: filter.ids, direct ids key, all-agents fallback
- Unknown agent ID skipped gracefully
- move-to-site / move-to-group with valid and missing targets
- manage-tags add and remove
- No-op actions (restart-services, fetch-logs, etc.)
"""
from fastapi.testclient import TestClient

BASE = "/web/api/v2.1"


def _act(client, auth_headers, action, body):
    return client.post(f"{BASE}/agents/actions/{action}", headers=auth_headers, json=body)


def _agent_id(client, auth_headers) -> str:
    return client.get(f"{BASE}/agents", headers=auth_headers).json()["data"][0]["id"]


def _agent(client, auth_headers, aid) -> dict:
    return client.get(f"{BASE}/agents/{aid}", headers=auth_headers).json()["data"]


class TestResolveIds:
    def test_filter_ids_key(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "connect", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_direct_ids_key(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "connect", {"ids": [aid]})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_all_agents_fallback(self, client: TestClient, auth_headers: dict) -> None:
        """Empty body → applies to all non-decommissioned agents."""
        resp = _act(client, auth_headers, "connect", {})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] > 1

    def test_unknown_agent_id_skipped(self, client: TestClient, auth_headers: dict) -> None:
        resp = _act(client, auth_headers, "connect", {"filter": {"ids": ["does-not-exist"]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 0


class TestAgentActions:
    def test_abort_scan(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "abort-scan", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1
        assert _agent(client, auth_headers, aid)["scanStatus"] == "aborted"

    def test_shutdown(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "shutdown", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_enable_agent(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "enable-agent", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert _agent(client, auth_headers, aid)["isActive"] is True

    def test_disable_agent(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "disable-agent", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert _agent(client, auth_headers, aid)["isActive"] is False

    def test_uninstall(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "uninstall", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert _agent(client, auth_headers, aid)["isPendingUninstall"] is True

    def test_mark_up_to_date(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "mark-up-to-date", {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert _agent(client, auth_headers, aid)["isUpToDate"] is True

    def test_randomize_uuid(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        old_uuid = _agent(client, auth_headers, aid)["uuid"]
        _act(client, auth_headers, "randomize-uuid", {"filter": {"ids": [aid]}})
        new_uuid = _agent(client, auth_headers, aid)["uuid"]
        assert new_uuid != old_uuid

    def test_decommission_sets_flags(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        _act(client, auth_headers, "decommission", {"filter": {"ids": [aid]}})
        agent = _agent(client, auth_headers, aid)
        assert agent["isDecommissioned"] is True
        assert agent["isActive"] is False


class TestMoveToSite:
    def test_move_to_site_valid(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        site_id = client.get(f"{BASE}/sites", headers=auth_headers).json()["data"]["sites"][0]["id"]
        resp = _act(client, auth_headers, "move-to-site", {
            "filter": {"ids": [aid]},
            "data": {"targetSiteId": site_id},
        })
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1
        assert _agent(client, auth_headers, aid)["siteId"] == site_id

    def test_move_to_site_unknown_site_is_noop(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = _agent_id(client, auth_headers)
        original_site = _agent(client, auth_headers, aid)["siteId"]
        _act(client, auth_headers, "move-to-site", {
            "filter": {"ids": [aid]},
            "data": {"targetSiteId": "nonexistent-site"},
        })
        assert _agent(client, auth_headers, aid)["siteId"] == original_site

    def test_move_to_site_missing_target_id_is_noop(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "move-to-site", {
            "filter": {"ids": [aid]},
            "data": {},
        })
        assert resp.status_code == 200


class TestMoveToGroup:
    def test_move_to_group_valid(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        group_id = client.get(f"{BASE}/groups", headers=auth_headers).json()["data"][0]["id"]
        resp = _act(client, auth_headers, "move-to-group", {
            "filter": {"ids": [aid]},
            "data": {"targetGroupId": group_id},
        })
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_move_to_group_unknown_group_is_noop(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = _agent_id(client, auth_headers)
        original_group = _agent(client, auth_headers, aid)["groupId"]
        _act(client, auth_headers, "move-to-group", {
            "filter": {"ids": [aid]},
            "data": {"targetGroupId": "nonexistent-group"},
        })
        assert _agent(client, auth_headers, aid)["groupId"] == original_group

    def test_move_to_group_missing_target_id_is_noop(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "move-to-group", {
            "filter": {"ids": [aid]},
            "data": {},
        })
        assert resp.status_code == 200


class TestManageTags:
    def test_add_tags(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        _act(client, auth_headers, "manage-tags", {
            "filter": {"ids": [aid]},
            "data": {"tagsToAdd": ["critical", "vip"], "tagsToRemove": []},
        })
        tag_keys = [t["key"] for t in _agent(client, auth_headers, aid)["tags"]["sentinelone"]]
        assert "critical" in tag_keys
        assert "vip" in tag_keys

    def test_remove_tags(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        _act(client, auth_headers, "manage-tags", {
            "filter": {"ids": [aid]},
            "data": {"tagsToAdd": ["removeme"], "tagsToRemove": []},
        })
        _act(client, auth_headers, "manage-tags", {
            "filter": {"ids": [aid]},
            "data": {"tagsToAdd": [], "tagsToRemove": ["removeme"]},
        })
        tag_keys = [t["key"] for t in _agent(client, auth_headers, aid)["tags"]["sentinelone"]]
        assert "removeme" not in tag_keys


class TestNoOpActions:
    """These actions only log activity — no state change — but must not error."""

    def _run(self, client, auth_headers, action):
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, action, {"filter": {"ids": [aid]}})
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_restart_services(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "restart-services")

    def test_fetch_logs(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "fetch-logs")

    def test_broadcast(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "broadcast")

    def test_restart_machine(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "restart-machine")

    def test_set_external_id(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "set-external-id")

    def test_fetch_installed_apps(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "fetch-installed-apps")

    def test_fetch_firewall_rules(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "fetch-firewall-rules")

    def test_reset_local_config(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "reset-local-config")

    def test_move_to_console(self, client: TestClient, auth_headers: dict) -> None:
        self._run(client, auth_headers, "move-to-console")


class TestUnknownAction:
    def test_unknown_action_returns_400(
        self, client: TestClient, auth_headers: dict
    ) -> None:
        """Unrecognised action returns 400 Bad Request."""
        aid = _agent_id(client, auth_headers)
        resp = _act(client, auth_headers, "totally-unknown-action", {"filter": {"ids": [aid]}})
        assert resp.status_code == 400


class TestFetchFiles:
    def test_fetch_files_returns_200(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = client.post(
            f"{BASE}/agents/{aid}/actions/fetch-files",
            headers=auth_headers,
            json={"data": {"files": ["/etc/passwd"], "password": "s3cr3t"}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 1

    def test_fetch_files_unknown_agent_returns_200_zero(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.post(
            f"{BASE}/agents/does-not-exist/actions/fetch-files",
            headers=auth_headers,
            json={"data": {"files": ["/etc/passwd"], "password": "x"}},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["affected"] == 0

    def test_fetch_files_creates_activity(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        client.post(
            f"{BASE}/agents/{aid}/actions/fetch-files",
            headers=auth_headers,
            json={"data": {"files": ["/tmp/sample.txt"], "password": "pw"}},
        )
        activities = client.get(
            f"{BASE}/activities",
            headers=auth_headers,
            params={"agentIds": aid, "activityTypes": 80, "limit": 200},
        ).json()["data"]
        assert any(a["activityType"] == 80 for a in activities)

    def test_download_upload_after_fetch(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        client.post(
            f"{BASE}/agents/{aid}/actions/fetch-files",
            headers=auth_headers,
            json={"data": {"files": ["/tmp/test.txt"], "password": "pw"}},
        )
        # Find the activity created for this fetch
        activities = client.get(
            f"{BASE}/activities",
            headers=auth_headers,
            params={"agentIds": aid, "activityTypes": 80, "limit": 200},
        ).json()["data"]
        activity_id = activities[-1]["id"]
        resp = client.get(
            f"{BASE}/agents/{aid}/uploads/{activity_id}",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert len(resp.content) > 0

    def test_download_upload_missing_activity_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        aid = _agent_id(client, auth_headers)
        resp = client.get(
            f"{BASE}/agents/{aid}/uploads/no-such-activity",
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_download_upload_unknown_agent_returns_404(self, client: TestClient, auth_headers: dict) -> None:
        resp = client.get(
            f"{BASE}/agents/no-such-agent/uploads/any-id",
            headers=auth_headers,
        )
        assert resp.status_code == 404
