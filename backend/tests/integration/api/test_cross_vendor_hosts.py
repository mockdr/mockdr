"""One physical host tells one story, whichever vendor is asked.

Every vendor's endpoint inventory is built from the SentinelOne fleet, so a
host is one machine seen through eight consoles. Each console used to draw
its own facts about it: Intune a random serial number and model, Cortex a
random user, the domain `ACMECORP` and a routable public address, Elastic
one OS string per OS family, and each its own idea of which hosts were
isolated. A SOAR playbook that pivots from one console to another — the
whole point of a cross-vendor integration — found the facts disagreeing.
And the fleet itself contradicted its own names: `RHEL-…` hosts running
Ubuntu, Windows 10 workstations named `SERVER-…`, rack servers that were
ThinkPads.
"""
from __future__ import annotations

import ipaddress

import pytest
from fastapi.testclient import TestClient

from infrastructure.seeders._shared import MACHINE_HARDWARE, MODELS_BY_KIND


def _agents() -> list:
    from repository.agent_repo import agent_repo

    return agent_repo.list_all()


def _with_other_seeds(check: object, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run *check* against several draws, not only the one this install has."""
    from infrastructure import seed

    try:
        for value in (7, 1337, 2024):
            monkeypatch.setattr(seed, "SEED", value)
            seed.generate_all()
            check()  # type: ignore[operator]
    finally:
        monkeypatch.undo()
        seed.generate_all()


class TestTheFleetMatchesItsOwnNames:
    """S1, the source every other vendor reads, is consistent with itself."""

    @staticmethod
    def _check() -> None:
        for agent in _agents():
            prefix = agent.computerName.split("-")[0]
            if agent.osType == "windows":
                assert (prefix == "SERVER") == ("Server" in agent.osName), (
                    agent.computerName, agent.osName)
            if agent.osType == "linux":
                if prefix == "RHEL":
                    assert "Red Hat" in agent.osName, (agent.computerName, agent.osName)
                if prefix == "UBUNTU":
                    assert "Ubuntu" in agent.osName, (agent.computerName, agent.osName)
            kind = "macos" if agent.osType == "macos" else agent.machineType
            assert agent.modelName in MODELS_BY_KIND[kind], (
                agent.computerName, agent.machineType, agent.modelName)
            if agent.machineType != "server":
                assert not agent.cloudProviders, agent.computerName

    def test_hostnames_and_models_fit_the_os(self, client: TestClient) -> None:
        self._check()

    def test_they_fit_for_other_draws_too(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _with_other_seeds(self._check, monkeypatch)

    def test_some_agents_are_isolated_and_report_it(self, client: TestClient) -> None:
        """Isolation needs a source of truth, and S1 isolated nobody."""
        isolated = [a for a in _agents() if a.networkQuarantineEnabled]
        assert isolated
        assert all(a.networkStatus == "disconnected" for a in isolated)


def _copy(collection: str, key: str) -> dict[str, object]:
    """S1 agent id → the record *collection* holds for it, via ``edr_id_map``."""
    from repository.store import store

    found = {}
    for agent_id, mapping in store.get_all_with_keys("edr_id_map").items():
        if isinstance(mapping, dict) and key in mapping:
            found[agent_id] = store.get(collection, mapping[key])
    # A comparison over no copies passes whatever the copies say.
    assert found, f"no {collection} record is mapped to an S1 agent"
    return found


class TestEveryVendorReadsTheHostFromS1:
    """The facts S1 holds about a host are the facts every copy reports."""

    def test_every_copy_is_in_the_id_map(self, client: TestClient) -> None:
        """Cortex and Elastic endpoints could not be joined to their agent."""
        agents = {a.id for a in _agents()}
        for collection, key in [
            ("xdr_endpoints", "xdr_endpoint_id"), ("es_endpoints", "es_agent_id"),
            ("cs_hosts", "cs_device_id"), ("mde_machines", "mde_machine_id"),
            ("graph_managed_devices", "graph_managed_device_id"),
        ]:
            copies = _copy(collection, key)
            assert set(copies) == agents, collection
            assert all(copy is not None for copy in copies.values()), collection

    def test_isolation_is_s1s(self, client: TestClient) -> None:
        agents = {a.id: a for a in _agents()}
        for agent_id, endpoint in _copy("xdr_endpoints", "xdr_endpoint_id").items():
            expected = "AGENT_ISOLATED" if agents[agent_id].networkQuarantineEnabled else "AGENT_UNISOLATED"
            assert endpoint.is_isolated == expected  # type: ignore[attr-defined]
        for agent_id, endpoint in _copy("es_endpoints", "es_agent_id").items():
            expected = "isolated" if agents[agent_id].networkQuarantineEnabled else "normal"
            assert endpoint.isolation_status == expected  # type: ignore[attr-defined]

    def test_cortex_endpoints_carry_s1s_user_domain_address_and_dates(
        self, client: TestClient,
    ) -> None:
        from utils.event_time import parse_epoch

        agents = {a.id: a for a in _agents()}
        for agent_id, endpoint in _copy("xdr_endpoints", "xdr_endpoint_id").items():
            agent = agents[agent_id]
            ep = endpoint.__dict__  # type: ignore[attr-defined]
            assert agent.lastLoggedInUserName in ep["users"]
            assert ep["domain"] == agent.domain
            assert ep["public_ip"] == [agent.externalIp]
            # A documentation range, not somebody's routable address.
            assert not ipaddress.ip_address(ep["public_ip"][0]).is_global
            assert ep["first_seen"] == int(parse_epoch(agent.createdAt) * 1000)  # type: ignore[operator]
            assert ep["last_seen"] == int(parse_epoch(agent.lastActiveDate) * 1000)  # type: ignore[operator]

    def test_defender_lists_s1s_user_among_those_logged_on(
        self, client: TestClient,
    ) -> None:
        agents = {a.id: a for a in _agents()}
        for agent_id, machine in _copy("mde_machines", "mde_machine_id").items():
            names = [u["accountName"] for u in machine.loggedOnUsers]  # type: ignore[attr-defined]
            assert agents[agent_id].lastLoggedInUserName in names

    def test_elastic_reports_the_hosts_own_os(self, client: TestClient) -> None:
        agents = {a.id: a for a in _agents()}
        for agent_id, endpoint in _copy("es_endpoints", "es_agent_id").items():
            assert endpoint.host_os_full == agents[agent_id].osName  # type: ignore[attr-defined]

    def test_intune_reports_s1s_hardware(self, client: TestClient) -> None:
        agents = {a.id: a for a in _agents()}
        for agent_id, device in _copy(
            "graph_managed_devices", "graph_managed_device_id",
        ).items():
            agent = agents[agent_id]
            assert device.serialNumber == agent.serialNumber  # type: ignore[attr-defined]
            assert (device.manufacturer, device.model) == (  # type: ignore[attr-defined]
                MACHINE_HARDWARE[agent.modelName])
