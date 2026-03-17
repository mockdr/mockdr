"""MDE machines seeder -- maps existing S1 agents to MDE machine records."""
from __future__ import annotations

import random

from faker import Faker

from domain.mde_machine import MdeMachine
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.mde_shared import (
    MDE_AGENT_VERSIONS,
    MDE_EXPOSURE_LEVELS,
    MDE_HEALTH_STATUSES,
    MDE_RISK_SCORES,
    mde_guid,
)
from repository.agent_repo import agent_repo
from repository.mde_machine_repo import mde_machine_repo
from repository.store import store

_OS_PLATFORM_MAP: dict[str, str] = {
    "windows": "Windows10",
    "macos": "macOS",
    "linux": "Linux",
}

_OS_PLATFORM_SERVER: str = "WindowsServer2022"

_TAG_POOL: list[str] = ["Production", "Development", "Staging", "Critical", "VIP"]

_LOGON_TYPES: list[str] = ["Interactive", "Network", "RemoteInteractive", "Service"]


def seed_mde_machines(fake: Faker) -> list[str]:
    """Create MDE machine records from existing S1 agent fleet.

    Reads every S1 agent from ``agent_repo`` and creates a corresponding
    ``MdeMachine`` record with equivalent data in MDE field format.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of ``machineId`` strings.
    """
    s1_agents = agent_repo.list_all()
    machine_ids: list[str] = []

    for agent in s1_agents:
        machine_id = mde_guid()
        machine_ids.append(machine_id)

        # Store agent↔machine mapping for cross-EDR views
        mapping = store.get("edr_id_map", agent.id) or {}
        mapping["mde_machine_id"] = machine_id
        store.save("edr_id_map", agent.id, mapping)

        # Determine OS platform
        if agent.osType == "windows" and agent.machineType == "server":
            os_platform = _OS_PLATFORM_SERVER
        else:
            os_platform = _OS_PLATFORM_MAP.get(agent.osType, "Windows10")

        # Build IP addresses list from network interfaces
        ip_addresses: list[dict] = []
        for iface in agent.networkInterfaces:
            for ip in iface.get("inet", []):
                ip_addresses.append({
                    "ipAddress": ip,
                    "macAddress": iface.get("physical", ""),
                    "operationalStatus": "Up",
                    "type": "Ethernet",
                })

        # Generate logged-on users
        user_count = random.randint(2, 4)
        logged_on_users: list[dict] = []
        for _ in range(user_count):
            logged_on_users.append({
                "accountName": fake.user_name(),
                "domainName": "ACMECORP",
                "logonType": random.choice(_LOGON_TYPES),
                "firstSeen": rand_ago(30),
                "lastSeen": rand_ago(1),
            })

        # Random machine tags
        tag_count = random.randint(0, 3)
        machine_tags = random.sample(_TAG_POOL, tag_count)

        # RBAC group from agent group
        rbac_group_id = hash(agent.groupId) % 10000
        rbac_group_name = agent.groupName

        # Determine last IP address
        last_ip = agent.lastIpToMgmt or (
            agent.networkInterfaces[0]["inet"][0]
            if agent.networkInterfaces
            else fake.ipv4_private()
        )

        mde_machine_repo.save(MdeMachine(
            machineId=machine_id,
            computerDnsName=agent.computerName,
            osPlatform=os_platform,
            osVersion=agent.osName,
            osProcessor="x64" if agent.osArch == "64 bit" else "x86",
            osBuild=int(agent.osRevision) if agent.osRevision.isdigit() else 0,
            healthStatus=random.choice(MDE_HEALTH_STATUSES),
            riskScore=random.choice(MDE_RISK_SCORES) or "None",
            exposureLevel=random.choice(MDE_EXPOSURE_LEVELS) or "None",
            onboardingStatus="Onboarded",
            sensorHealthState=random.choice(["Active"] * 9 + ["Inactive"]),
            lastSeen=agent.lastActiveDate,
            firstSeen=agent.createdAt,
            machineTags=machine_tags,
            rbacGroupId=rbac_group_id,
            rbacGroupName=rbac_group_name,
            aadDeviceId=mde_guid(),
            isAadJoined=True,
            lastIpAddress=last_ip,
            lastExternalIpAddress=agent.externalIp,
            ipAddresses=ip_addresses,
            agentVersion=random.choice(MDE_AGENT_VERSIONS),
            loggedOnUsers=logged_on_users,
            groupName=agent.groupName,
            managedBy="MDE",
            managedByStatus="Active",
        ))

    return machine_ids
