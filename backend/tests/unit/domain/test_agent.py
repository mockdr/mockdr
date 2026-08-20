"""Unit tests for the Agent domain dataclass.

Verifies structural invariants: AGENT_INTERNAL_FIELDS membership,
required public field presence, and internal/public field segregation.
"""
import pytest

from domain.agent import Agent
from repository.agent_repo import agent_repo
from utils.internal_fields import AGENT_INTERNAL_FIELDS


class TestAgentInternalFields:
    """AGENT_INTERNAL_FIELDS must contain exactly the fields stripped before API responses."""

    def test_is_a_set(self) -> None:
        assert isinstance(AGENT_INTERNAL_FIELDS, (set, frozenset))

    def test_contains_passphrase(self) -> None:
        assert "passphrase" in AGENT_INTERNAL_FIELDS

    def test_contains_local_ip(self) -> None:
        assert "localIp" in AGENT_INTERNAL_FIELDS

    def test_contains_is_infected(self) -> None:
        assert "isInfected" in AGENT_INTERNAL_FIELDS

    def test_contains_installed_at(self) -> None:
        assert "installedAt" in AGENT_INTERNAL_FIELDS

    def test_contains_agent_license_type(self) -> None:
        assert "agentLicenseType" in AGENT_INTERNAL_FIELDS

    def test_contains_cpu_usage(self) -> None:
        assert "cpuUsage" in AGENT_INTERNAL_FIELDS

    def test_contains_memory_usage(self) -> None:
        assert "memoryUsage" in AGENT_INTERNAL_FIELDS

    def test_does_not_contain_public_fields(self) -> None:
        public_fields = {"id", "uuid", "computerName", "osType", "agentVersion",
                         "networkStatus", "infected", "lastIpToMgmt"}
        assert public_fields.isdisjoint(AGENT_INTERNAL_FIELDS), (
            f"Public fields found in AGENT_INTERNAL_FIELDS: "
            f"{public_fields & AGENT_INTERNAL_FIELDS}"
        )


class TestAgentDataclass:
    """Agent dataclass must expose the correct public API fields on seeded instances."""

    @pytest.fixture()
    def seeded_agent(self) -> Agent:
        """Return the first seeded agent from the in-memory repository."""
        return agent_repo.list_all()[0]

    def test_id_field_is_str(self, seeded_agent: Agent) -> None:
        assert isinstance(seeded_agent.id, str)
        assert len(seeded_agent.id) > 0

    def test_computer_name_is_str(self, seeded_agent: Agent) -> None:
        assert isinstance(seeded_agent.computerName, str)

    def test_infected_is_boolean(self, seeded_agent: Agent) -> None:
        assert isinstance(seeded_agent.infected, bool)

    def test_active_threats_is_int(self, seeded_agent: Agent) -> None:
        assert isinstance(seeded_agent.activeThreats, int)

    def test_internal_fields_present_on_dataclass(self, seeded_agent: Agent) -> None:
        """Internal fields exist on the dataclass (stripped by the query layer, not here)."""
        assert hasattr(seeded_agent, "passphrase")
        assert hasattr(seeded_agent, "localIp")
        assert hasattr(seeded_agent, "isInfected")

    def test_infected_and_is_infected_match(self, seeded_agent: Agent) -> None:
        """'infected' (public) must mirror 'isInfected' (internal alias) at domain level."""
        assert seeded_agent.infected == seeded_agent.isInfected

    def test_last_ip_matches_local_ip(self, seeded_agent: Agent) -> None:
        """'lastIpToMgmt' (public) must be set from 'localIp' during seed."""
        assert seeded_agent.lastIpToMgmt == seeded_agent.localIp


class TestProxyStates:
    """``proxyStates`` must carry every member the 2.1 spec defines.

    Only ``console`` and ``deepVisibility`` were present, so a client reading
    the addresses or the PAC fields off an agent got a KeyError against the
    mock and a value against a real console. Caught by the field-drift check,
    which had never run in CI because its spec was absent.
    """

    SPEC_MEMBERS = frozenset({  # noqa: RUF012
        "console",
        "consoleProxyAddress",
        "deepVisibility",
        "deepVisibilityProxyAddress",
        "pacFileUsage",
        "proxyMethod",
    })

    def _states(self) -> dict:
        """Return proxyStates from a seeded agent, as the API would serve it."""
        agents = agent_repo.list_all()
        assert agents, "seed produced no agents"
        return dict(agents[0].proxyStates)

    def test_seeded_agent_carries_every_spec_member(self) -> None:
        assert set(self._states()) == self.SPEC_MEMBERS

    def test_member_types_match_the_spec(self) -> None:
        """The spec types three of these as boolean and three as string."""
        states = self._states()
        for name in ("console", "deepVisibility", "pacFileUsage"):
            assert isinstance(states[name], bool), name
        for name in ("consoleProxyAddress", "deepVisibilityProxyAddress", "proxyMethod"):
            assert isinstance(states[name], str), name
