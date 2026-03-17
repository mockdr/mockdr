"""Elastic Security endpoints seeder -- maps existing S1 agents to ES endpoint records."""
from __future__ import annotations

import random

from faker import Faker

from domain.es_endpoint import EsEndpoint
from infrastructure.seeders.es_shared import ES_POLICY_NAMES, es_uuid
from repository.agent_repo import agent_repo
from repository.es_endpoint_repo import es_endpoint_repo

_OS_MAP: dict[str, str] = {
    "windows": "Windows",
    "macos": "macOS",
    "linux": "Linux",
}

_OS_FULL_MAP: dict[str, str] = {
    "windows": "Windows 10 Pro 22H2",
    "macos": "macOS Sonoma 14.3",
    "linux": "Ubuntu 22.04 LTS",
}

_ARCH_MAP: dict[str, str] = {
    "windows": "x86_64",
    "macos": "aarch64",
    "linux": "x86_64",
}

_STATUS_WEIGHTS: list[str] = (
    ["online"] * 17
    + ["offline"] * 2
    + ["inactive"]
)

_ISOLATION_WEIGHTS: list[str] = (
    ["normal"] * 19
    + ["isolated"]
)


def seed_es_endpoints(fake: Faker) -> list[str]:
    """Create Elastic Security endpoint records from existing S1 agent fleet.

    Reads every S1 agent from ``agent_repo`` and creates a corresponding
    ``EsEndpoint`` record with equivalent data in Elastic field format.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of ``agent_id`` strings.
    """
    s1_agents = agent_repo.list_all()
    agent_ids: list[str] = []

    for agent in s1_agents:
        agent_id = es_uuid()
        agent_ids.append(agent_id)

        os_name = _OS_MAP.get(agent.osType, "Windows")
        os_full = _OS_FULL_MAP.get(agent.osType, "Windows 10 Pro 22H2")
        architecture = _ARCH_MAP.get(agent.osType, "x86_64")

        # Build network fields from interfaces
        host_ips: list[str] = []
        host_macs: list[str] = []
        if agent.networkInterfaces:
            for iface in agent.networkInterfaces:
                for ip in iface.get("inet", []):
                    host_ips.append(ip)
                phys = iface.get("physical", "")
                if phys:
                    host_macs.append(phys)
        if not host_ips:
            host_ips = [fake.ipv4_private()]

        policy_name = random.choice(ES_POLICY_NAMES)
        status = random.choice(_STATUS_WEIGHTS)
        isolation = random.choice(_ISOLATION_WEIGHTS)

        es_endpoint_repo.save(EsEndpoint(
            agent_id=agent_id,
            hostname=agent.computerName,
            host_ip=host_ips,
            host_mac=host_macs,
            host_os_name=os_name,
            host_os_version=agent.osRevision,
            host_os_full=os_full,
            host_architecture=architecture,
            agent_version=agent.agentVersion,
            agent_status=status,
            agent_type="endpoint",
            policy_id=es_uuid(),
            policy_name=policy_name,
            policy_revision=random.randint(1, 15),
            enrolled_at=agent.createdAt,
            last_checkin=agent.lastActiveDate,
            isolation_status=isolation,
            metadata={
                "host_type": agent.machineType,
                "domain": agent.domain,
                "serial_number": agent.serialNumber,
            },
        ))

    return agent_ids
