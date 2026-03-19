"""Unit tests for application.agents.commands — agent action execution."""
import pytest

from application.agents.commands import execute_action, fetch_files
from infrastructure.seed import generate_all
from repository.activity_repo import activity_repo
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.tag_repo import tag_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


def _first_agent_id() -> str:
    return agent_repo.list_all()[0].id


def _first_agent():
    return agent_repo.list_all()[0]


# ── _resolve_ids ────────────────────────────────────────────────────────────


class TestResolveIds:
    """Tests for ID resolution from various body formats."""

    def test_filter_ids_format(self) -> None:
        aid = _first_agent_id()
        result = execute_action("connect", {"filter": {"ids": [aid]}})
        assert result["data"]["affected"] == 1

    def test_ids_format(self) -> None:
        aid = _first_agent_id()
        result = execute_action("connect", {"ids": [aid]})
        assert result["data"]["affected"] == 1

    def test_no_ids_applies_to_all_non_decommissioned(self) -> None:
        non_decom = [a for a in agent_repo.list_all() if not a.isDecommissioned]
        result = execute_action("connect", {})
        assert result["data"]["affected"] == len(non_decom)


# ── Unknown action ──────────────────────────────────────────────────────────


class TestUnknownAction:
    """Tests for unknown action handling."""

    def test_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown agent action"):
            execute_action("not-a-real-action", {"ids": [_first_agent_id()]})


# ── connect / disconnect ────────────────────────────────────────────────────


class TestConnectDisconnect:
    """Tests for connect and disconnect actions."""

    def test_connect_sets_connected(self) -> None:
        aid = _first_agent_id()
        execute_action("connect", {"ids": [aid]})
        assert agent_repo.get(aid).networkStatus == "connected"

    def test_disconnect_sets_disconnected(self) -> None:
        aid = _first_agent_id()
        execute_action("disconnect", {"ids": [aid]})
        assert agent_repo.get(aid).networkStatus == "disconnected"

    def test_disconnect_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        execute_action("disconnect", {"ids": [_first_agent_id()]})
        assert len(activity_repo.list_all()) > before

    def test_disconnect_activity_type_52(self) -> None:
        execute_action("disconnect", {"ids": [_first_agent_id()]})
        latest = activity_repo.list_all()[0]
        assert latest.activityType == 52

    def test_connect_activity_type_53(self) -> None:
        execute_action("connect", {"ids": [_first_agent_id()]})
        latest = activity_repo.list_all()[0]
        assert latest.activityType == 53


# ── scan actions ────────────────────────────────────────────────────────────


class TestScanActions:
    """Tests for initiate-scan and abort-scan actions."""

    def test_initiate_scan_sets_started(self) -> None:
        aid = _first_agent_id()
        execute_action("initiate-scan", {"ids": [aid]})
        agent = agent_repo.get(aid)
        assert agent.scanStatus == "started"
        assert agent.scanStartedAt is not None

    def test_abort_scan_sets_aborted(self) -> None:
        aid = _first_agent_id()
        execute_action("abort-scan", {"ids": [aid]})
        agent = agent_repo.get(aid)
        assert agent.scanStatus == "aborted"
        assert agent.scanAbortedAt is not None


# ── enable / disable / shutdown ─────────────────────────────────────────────


class TestActiveStateActions:
    """Tests for shutdown, enable-agent, disable-agent."""

    def test_shutdown_deactivates(self) -> None:
        aid = _first_agent_id()
        execute_action("shutdown", {"ids": [aid]})
        assert agent_repo.get(aid).isActive is False

    def test_enable_agent(self) -> None:
        aid = _first_agent_id()
        execute_action("disable-agent", {"ids": [aid]})
        execute_action("enable-agent", {"ids": [aid]})
        assert agent_repo.get(aid).isActive is True

    def test_disable_agent(self) -> None:
        aid = _first_agent_id()
        execute_action("disable-agent", {"ids": [aid]})
        assert agent_repo.get(aid).isActive is False


# ── uninstall / decommission ────────────────────────────────────────────────


class TestUninstallDecommission:
    """Tests for uninstall and decommission actions."""

    def test_uninstall_sets_pending(self) -> None:
        aid = _first_agent_id()
        execute_action("uninstall", {"ids": [aid]})
        assert agent_repo.get(aid).isPendingUninstall is True

    def test_decommission_sets_flags(self) -> None:
        aid = _first_agent_id()
        execute_action("decommission", {"ids": [aid]})
        agent = agent_repo.get(aid)
        assert agent.isDecommissioned is True
        assert agent.isActive is False


# ── mark-up-to-date / randomize-uuid ───────────────────────────────────────


class TestMiscActions:
    """Tests for mark-up-to-date and randomize-uuid."""

    def test_mark_up_to_date(self) -> None:
        aid = _first_agent_id()
        execute_action("mark-up-to-date", {"ids": [aid]})
        assert agent_repo.get(aid).isUpToDate is True

    def test_randomize_uuid_changes_uuid(self) -> None:
        aid = _first_agent_id()
        old_uuid = agent_repo.get(aid).uuid
        execute_action("randomize-uuid", {"ids": [aid]})
        new_uuid = agent_repo.get(aid).uuid
        assert new_uuid != old_uuid


# ── move-to-site ────────────────────────────────────────────────────────────


class TestMoveToSite:
    """Tests for the move-to-site action."""

    def test_moves_agent_to_target_site(self) -> None:
        agent = _first_agent()
        sites = site_repo.list_all()
        # Find a different site
        target = next((s for s in sites if s.id != agent.siteId), None)
        if target is None:
            pytest.skip("Only one site in seed data")
        groups = group_repo.get_by_site(target.id)
        execute_action("move-to-site", {
            "ids": [agent.id],
            "data": {"targetSiteId": target.id},
        })
        updated = agent_repo.get(agent.id)
        assert updated.siteId == target.id
        assert updated.siteName == target.name
        if groups:
            default_group = next((g for g in groups if g.isDefault), groups[0])
            assert updated.groupId == default_group.id
            assert updated.groupName == default_group.name

    def test_move_to_site_nonexistent_site_noop(self) -> None:
        aid = _first_agent_id()
        old_site = agent_repo.get(aid).siteId
        execute_action("move-to-site", {
            "ids": [aid],
            "data": {"targetSiteId": "nonexistent-site"},
        })
        assert agent_repo.get(aid).siteId == old_site


# ── move-to-group ───────────────────────────────────────────────────────────


class TestMoveToGroup:
    """Tests for the move-to-group action."""

    def test_moves_agent_to_target_group(self) -> None:
        agent = _first_agent()
        groups = group_repo.list_all()
        target = next((g for g in groups if g.id != agent.groupId), None)
        if target is None:
            pytest.skip("Only one group in seed data")
        execute_action("move-to-group", {
            "ids": [agent.id],
            "data": {"targetGroupId": target.id},
        })
        updated = agent_repo.get(agent.id)
        assert updated.groupId == target.id
        assert updated.groupName == target.name

    def test_move_to_group_nonexistent_group_noop(self) -> None:
        aid = _first_agent_id()
        old_group = agent_repo.get(aid).groupId
        execute_action("move-to-group", {
            "ids": [aid],
            "data": {"targetGroupId": "nonexistent-group"},
        })
        assert agent_repo.get(aid).groupId == old_group


# ── manage-tags (real S1 format) ────────────────────────────────────────────


class TestManageTagsS1Format:
    """Tests for manage-tags with real S1 format operations."""

    def test_add_tag_via_s1_format(self) -> None:
        aid = _first_agent_id()
        tags = tag_repo.list_all()
        if not tags:
            pytest.skip("No tags in seed data")
        tag = tags[0]
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tag.id, "operation": "add"}],
        }, actor_user_id="user-1")
        updated = agent_repo.get(aid)
        tag_ids = [t["id"] for t in updated.tags.get("sentinelone", [])]
        assert tag.id in tag_ids

    def test_remove_tag_via_s1_format(self) -> None:
        aid = _first_agent_id()
        tags = tag_repo.list_all()
        if not tags:
            pytest.skip("No tags in seed data")
        tag = tags[0]
        # Add first, then remove
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tag.id, "operation": "add"}],
        })
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tag.id, "operation": "remove"}],
        })
        updated = agent_repo.get(aid)
        tag_ids = [t["id"] for t in updated.tags.get("sentinelone", [])]
        assert tag.id not in tag_ids

    def test_override_replaces_all_tags(self) -> None:
        aid = _first_agent_id()
        tags = tag_repo.list_all()
        if len(tags) < 2:
            pytest.skip("Need at least 2 tags")
        # Add first tag
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tags[0].id, "operation": "add"}],
        })
        # Override with second tag
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tags[1].id, "operation": "override"}],
        })
        updated = agent_repo.get(aid)
        s1_tags = updated.tags.get("sentinelone", [])
        assert len(s1_tags) == 1
        assert s1_tags[0]["id"] == tags[1].id

    def test_add_duplicate_tag_ignored(self) -> None:
        aid = _first_agent_id()
        tags = tag_repo.list_all()
        if not tags:
            pytest.skip("No tags in seed data")
        tag = tags[0]
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tag.id, "operation": "add"}],
        })
        execute_action("manage-tags", {
            "ids": [aid],
            "data": [{"tagId": tag.id, "operation": "add"}],
        })
        updated = agent_repo.get(aid)
        count = sum(1 for t in updated.tags.get("sentinelone", []) if t["id"] == tag.id)
        assert count == 1


# ── manage-tags (legacy format) ────────────────────────────────────────────


class TestManageTagsLegacyFormat:
    """Tests for manage-tags with legacy tagsToAdd/tagsToRemove format."""

    def test_add_tag_by_key(self) -> None:
        aid = _first_agent_id()
        execute_action("manage-tags", {
            "ids": [aid],
            "data": {"tagsToAdd": ["test-key"], "tagsToRemove": []},
        })
        updated = agent_repo.get(aid)
        keys = [t["key"] for t in updated.tags.get("sentinelone", [])]
        assert "test-key" in keys

    def test_remove_tag_by_key(self) -> None:
        aid = _first_agent_id()
        # Add first
        execute_action("manage-tags", {
            "ids": [aid],
            "data": {"tagsToAdd": ["remove-me"], "tagsToRemove": []},
        })
        # Then remove
        execute_action("manage-tags", {
            "ids": [aid],
            "data": {"tagsToAdd": [], "tagsToRemove": ["remove-me"]},
        })
        updated = agent_repo.get(aid)
        keys = [t["key"] for t in updated.tags.get("sentinelone", [])]
        assert "remove-me" not in keys


# ── no-op actions ───────────────────────────────────────────────────────────


class TestNoOpActions:
    """Tests for actions that only log activity (restart-services, fetch-logs, etc.)."""

    @pytest.mark.parametrize("action", [
        "restart-services", "fetch-logs", "broadcast", "restart-machine",
        "set-external-id", "fetch-installed-apps", "fetch-firewall-rules",
        "reset-local-config", "move-to-console",
    ])
    def test_noop_action_returns_affected(self, action: str) -> None:
        aid = _first_agent_id()
        result = execute_action(action, {"ids": [aid]})
        assert result["data"]["affected"] == 1

    @pytest.mark.parametrize("action", [
        "restart-services", "fetch-logs",
    ])
    def test_noop_action_creates_activity(self, action: str) -> None:
        before = len(activity_repo.list_all())
        execute_action(action, {"ids": [_first_agent_id()]})
        assert len(activity_repo.list_all()) > before


# ── nonexistent agent ───────────────────────────────────────────────────────


class TestNonexistentAgent:
    """Tests for actions targeting a nonexistent agent."""

    def test_nonexistent_agent_not_counted(self) -> None:
        result = execute_action("connect", {"ids": ["does-not-exist"]})
        assert result["data"]["affected"] == 0


# ── fetch_files ─────────────────────────────────────────────────────────────


class TestFetchFiles:
    """Tests for the fetch_files command."""

    def test_returns_affected_one(self) -> None:
        aid = _first_agent_id()
        result = fetch_files(aid, ["/etc/passwd"], "password123")
        assert result["data"]["affected"] == 1

    def test_nonexistent_agent_returns_zero(self) -> None:
        result = fetch_files("nonexistent", ["/etc/passwd"], "password123")
        assert result["data"]["affected"] == 0

    def test_creates_activity(self) -> None:
        before = len(activity_repo.list_all())
        fetch_files(_first_agent_id(), ["/tmp/test.txt"], "pw")
        assert len(activity_repo.list_all()) > before

    def test_stores_zip_in_uploads(self) -> None:
        from repository.store import store
        aid = _first_agent_id()
        fetch_files(aid, ["/tmp/test.txt"], "pw")
        # The upload is stored keyed by the activity ID
        activities = activity_repo.list_all()
        latest = activities[0]
        data = store.get("agent_uploads", latest.id)
        assert data is not None
        assert len(data) > 0
