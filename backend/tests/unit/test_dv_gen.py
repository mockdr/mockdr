"""Unit tests for the Deep Visibility event generator.

Covers:
- ``_parse_agent_ids`` — DV query-string agent ID extraction
- ``generate_dv_events`` — grounded event generation against real agent data
"""
import pytest

from infrastructure.dv_gen import _parse_agent_ids, generate_dv_events
from repository.agent_repo import agent_repo
from repository.store import store

_REQUIRED_EVENT_FIELDS = frozenset({
    "id", "eventType", "createdAt",
    "agentName", "agentId", "agentOs", "agentIp",
    "processName", "processImagePath", "processCmd",
    "processGroupId", "processStartTime", "processUserName",
    "pid", "parentPid",
    "srcIp", "dstIp", "dstPort", "srcPort",
    "fileFullName", "fileSha256", "fileSha1", "fileMd5",
    "registryPath", "dnsRequest", "dnsResponse",
})


class TestParseAgentIds:
    def test_returns_empty_for_blank_query(self) -> None:
        assert _parse_agent_ids("") == []

    def test_returns_empty_for_short_quoted_values(self) -> None:
        # S1 IDs are 18-19 digits; short strings must not match
        assert _parse_agent_ids('EventType = "Process"') == []
        assert _parse_agent_ids('status = "12345"') == []

    def test_parses_equality_form(self) -> None:
        s1_id = "517353488675052695"  # 18-digit S1-style decimal ID
        result = _parse_agent_ids(f'AgentId = "{s1_id}"')
        assert result == [s1_id]

    def test_parses_in_form(self) -> None:
        id1 = "517353488675052695"
        id2 = "445634991597407727"
        result = _parse_agent_ids(f'AgentId In ("{id1}", "{id2}")')
        assert id1 in result
        assert id2 in result
        assert len(result) == 2

    def test_ignores_non_numeric_quoted_strings(self) -> None:
        # Date-like strings contain non-digit chars (T, Z, :) — must not match
        assert _parse_agent_ids('createdAt = "2024-01-01T00:00:00Z"') == []


class TestGenerateDvEvents:
    def test_returns_requested_count(self) -> None:
        events = generate_dv_events(count=10)
        assert len(events) == 10

    def test_default_count_is_fifty(self) -> None:
        events = generate_dv_events()
        assert len(events) == 50

    def test_event_has_required_fields(self) -> None:
        events = generate_dv_events(count=3)
        for event in events:
            assert _REQUIRED_EVENT_FIELDS <= event.keys(), (
                f"Missing fields: {_REQUIRED_EVENT_FIELDS - event.keys()}"
            )

    def test_events_reference_real_agent_ids(self) -> None:
        agent_ids = {a.id for a in agent_repo.list_all()}
        events = generate_dv_events(count=20)
        for event in events:
            assert event["agentId"] in agent_ids

    def test_agent_name_matches_computer_name(self) -> None:
        agents = {a.id: a.computerName for a in agent_repo.list_all()}
        events = generate_dv_events(count=20)
        for event in events:
            assert event["agentName"] == agents[event["agentId"]]

    def test_agent_ip_matches_last_ip_to_mgmt(self) -> None:
        agents = {a.id: a.lastIpToMgmt for a in agent_repo.list_all()}
        events = generate_dv_events(count=20)
        for event in events:
            assert event["agentIp"] == agents[event["agentId"]]

    def test_src_ip_matches_agent_ip(self) -> None:
        events = generate_dv_events(count=10)
        for event in events:
            assert event["srcIp"] == event["agentIp"]

    def test_agent_id_filter_restricts_to_target(self) -> None:
        target = agent_repo.list_all()[0]
        query_body = {"query": f'AgentId = "{target.id}"'}
        events = generate_dv_events(count=20, query_body=query_body)
        for event in events:
            assert event["agentId"] == target.id
            assert event["agentName"] == target.computerName

    def test_unknown_agent_id_filter_falls_back_to_all_agents(self) -> None:
        agent_ids = {a.id for a in agent_repo.list_all()}
        query_body = {"query": 'AgentId = "00000000-0000-0000-0000-000000000000"'}
        events = generate_dv_events(count=10, query_body=query_body)
        for event in events:
            assert event["agentId"] in agent_ids

    def test_infected_agent_gets_threat_event_types_only(self) -> None:
        threat_types = {"Process", "File", "Network", "DNS"}
        infected = next((a for a in agent_repo.list_all() if a.infected), None)
        if infected is None:
            pytest.skip("No infected agents in seed data — seed invariant violated")
        query_body = {"query": f'AgentId = "{infected.id}"'}
        events = generate_dv_events(count=50, query_body=query_body)
        for event in events:
            assert event["eventType"] in threat_types

    def test_empty_agent_store_falls_back_gracefully(self) -> None:
        store.clear("agents")
        events = generate_dv_events(count=5)
        # Must return the right count without crashing
        assert len(events) == 5
        # Fallback events use phantom agent names (ENDPOINT-XXXXXX pattern)
        for event in events:
            assert event["agentName"].startswith("ENDPOINT-")
