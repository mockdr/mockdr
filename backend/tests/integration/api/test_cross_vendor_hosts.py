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

import pytest
from fastapi.testclient import TestClient

from infrastructure.seeders._shared import MODELS_BY_KIND


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
