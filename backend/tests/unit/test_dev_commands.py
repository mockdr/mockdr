"""Unit tests for application.dev.commands — reset, export, import, scenarios."""
import pytest

from application.dev.commands import (
    export_state,
    import_state,
    reset,
    trigger_scenario,
)
from infrastructure.seed import generate_all
from repository.agent_repo import agent_repo
from repository.store import store
from repository.threat_repo import threat_repo


@pytest.fixture(autouse=True)
def _seed() -> None:
    generate_all()


# ── reset ────────────────────────────────────────────────────────────────────


class TestReset:
    """Tests for the reset command."""

    def test_returns_status(self) -> None:
        result = reset()
        assert result["data"]["status"] == "reset complete"

    def test_restores_agent_count(self) -> None:
        original = len(agent_repo.list_all())
        # Mutate state
        agent = agent_repo.list_all()[0]
        agent.isInfected = True
        # Reset
        reset()
        assert len(agent_repo.list_all()) == original


# ── export_state ─────────────────────────────────────────────────────────────


class TestExportState:
    """Tests for the export_state command."""

    def test_contains_typed_collections(self) -> None:
        snap = export_state()
        for key in ("agents", "threats", "sites", "groups", "users", "activities",
                     "exclusions", "policies", "firewall_rules", "iocs",
                     "accounts", "alerts", "device_control_rules", "dv_queries",
                     "webhook_subscriptions"):
            assert key in snap, f"Missing collection: {key}"

    def test_contains_raw_collections(self) -> None:
        snap = export_state()
        for key in ("installed_apps", "blocklist", "api_tokens"):
            assert key in snap, f"Missing raw collection: {key}"

    def test_contains_activity_order(self) -> None:
        snap = export_state()
        assert "_activity_order" in snap
        assert isinstance(snap["_activity_order"], list)

    def test_agents_are_dicts(self) -> None:
        """Exported agents must be plain dicts (via asdict), not dataclass instances."""
        snap = export_state()
        assert len(snap["agents"]) > 0
        assert isinstance(snap["agents"][0], dict)

    def test_agent_count_matches_repo(self) -> None:
        snap = export_state()
        assert len(snap["agents"]) == len(agent_repo.list_all())


# ── import_state ─────────────────────────────────────────────────────────────


class TestImportState:
    """Tests for the import_state command."""

    def test_round_trip_preserves_agent_count(self) -> None:
        snap = export_state()
        original_count = len(snap["agents"])
        result = import_state(snap)
        assert result["data"]["imported"] > 0
        assert len(agent_repo.list_all()) == original_count

    def test_round_trip_preserves_threat_count(self) -> None:
        snap = export_state()
        original_count = len(snap["threats"])
        import_state(snap)
        assert len(threat_repo.list_all()) == original_count

    def test_empty_snapshot_clears_store(self) -> None:
        result = import_state({})
        assert result["data"]["imported"] == 0

    def test_malformed_record_is_skipped(self) -> None:
        snap = export_state()
        good_count = len(snap["agents"])
        snap["agents"].append({"bad_field": True})
        import_state(snap)
        assert len(agent_repo.list_all()) == good_count

    def test_non_dict_raw_record_is_skipped(self) -> None:
        snap = export_state()
        snap["blocklist"].append("not-a-dict")
        # Should not crash
        import_state(snap)

    def test_raw_record_without_id_is_skipped(self) -> None:
        snap = export_state()
        snap["blocklist"].append({"value": "abc", "type": "black_hash"})
        # Should not crash
        import_state(snap)

    def test_activity_order_restored(self) -> None:
        snap = export_state()
        original_order = snap["_activity_order"]
        import_state(snap)
        assert store.get_activity_order() == original_order

    def test_fallback_when_no_activity_order(self) -> None:
        """When _activity_order is missing, import rebuilds order from createdAt."""
        snap = export_state()
        snap.pop("_activity_order")
        import_state(snap)
        # Activities should still be importable
        order = store.get_activity_order()
        assert len(order) > 0

    def test_total_imported_is_accurate(self) -> None:
        snap = export_state()
        result = import_state(snap)
        total = result["data"]["imported"]
        # Should be the sum of all records across all collections.
        # Exclude non-collection meta keys (_activity_order, _proxy_config).
        _meta_keys = {"_activity_order", "_proxy_config"}
        expected = sum(len(snap.get(k, [])) for k in snap if k not in _meta_keys)
        assert total == expected


# ── trigger_scenario ─────────────────────────────────────────────────────────


class TestTriggerScenario:
    """Tests for the trigger_scenario command."""

    def test_mass_infection_infects_agents(self) -> None:
        result = trigger_scenario("mass_infection")
        assert result["data"]["scenario"] == "mass_infection"
        affected = result["data"]["affected"]
        assert affected > 0
        infected = [a for a in agent_repo.list_all() if a.isInfected]
        assert len(infected) >= affected

    def test_agent_offline_disconnects_agents(self) -> None:
        result = trigger_scenario("agent_offline")
        assert result["data"]["scenario"] == "agent_offline"
        affected = result["data"]["affected"]
        assert affected > 0
        disconnected = [a for a in agent_repo.list_all() if a.networkStatus == "disconnected"]
        assert len(disconnected) >= affected

    def test_quiet_day_resolves_all_threats(self) -> None:
        result = trigger_scenario("quiet_day")
        assert result["data"]["scenario"] == "quiet_day"
        for threat in threat_repo.list_all():
            assert threat.threatInfo["incidentStatus"] == "resolved"
            assert threat.threatInfo["resolved"] is True
            assert threat.threatInfo["analystVerdict"] == "false_positive"

    def test_quiet_day_heals_all_agents(self) -> None:
        trigger_scenario("quiet_day")
        for agent in agent_repo.list_all():
            assert agent.isInfected is False
            assert agent.activeThreats == 0
            assert agent.networkStatus == "connected"
            assert agent.isActive is True

    def test_apt_campaign_infects_and_disconnects(self) -> None:
        result = trigger_scenario("apt_campaign")
        assert result["data"]["scenario"] == "apt_campaign"
        affected = result["data"]["affected"]
        assert affected > 0
        # All affected agents should be infected AND disconnected
        infected_disconnected = [
            a for a in agent_repo.list_all()
            if a.isInfected and a.networkStatus == "disconnected"
        ]
        assert len(infected_disconnected) >= affected

    def test_unknown_scenario_returns_error(self) -> None:
        result = trigger_scenario("nonexistent")
        assert "error" in result["data"]
        assert "nonexistent" in result["data"]["error"]

    def test_mass_infection_affected_capped_at_20(self) -> None:
        result = trigger_scenario("mass_infection")
        assert result["data"]["affected"] <= 20

    def test_apt_campaign_affected_capped_at_10(self) -> None:
        result = trigger_scenario("apt_campaign")
        assert result["data"]["affected"] <= 10
