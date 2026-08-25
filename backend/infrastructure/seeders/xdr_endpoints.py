"""XDR endpoints seeder -- maps existing S1 agents to XDR endpoint records."""
from __future__ import annotations

import random

from faker import Faker

from domain.xdr_endpoint import XdrEndpoint
from infrastructure.seeders.xdr_shared import (
    XDR_AGENT_VERSIONS,
    XDR_CONTENT_VERSIONS,
    XDR_ENDPOINT_STATUSES,
    rand_epoch_ms,
    xdr_id,
)
from repository.agent_repo import agent_repo
from repository.xdr_endpoint_repo import xdr_endpoint_repo

_OS_TYPE_MAP: dict[str, str] = {
    "windows": "windows",
    "macos": "macos",
    "linux": "linux",
}

_ENDPOINT_TYPE_MAP: dict[str, str] = {
    "server": "server",
    "laptop": "laptop",
    "desktop": "desktop",
}


#: The values Cortex XDR documents for these columns. A fleet where every
#: endpoint is unisolated and never scanned cannot exercise the filters the
#: API declares over them.
XDR_ISOLATION: list[str] = ["unisolated", "unisolated", "unisolated", "isolated"]
XDR_SCAN_STATES: list[str] = ["none", "success", "success", "in_progress", "canceled"]
XDR_OPERATIONAL: list[str] = [
    "protected", "protected", "protected", "partially_protected", "unprotected",
]
#: The installer an endpoint was enrolled with, which `dist_name` filters on.
XDR_INSTALL_PACKAGES: list[str] = [
    "Windows Standard Installer", "Linux Standard Installer",
    "macOS Standard Installer", "Windows VDI Installer",
]


def seed_xdr_endpoints(fake: Faker) -> list[str]:
    """Create XDR endpoint records from existing S1 agent fleet.

    Reads every S1 agent from ``agent_repo`` and creates a corresponding
    ``XdrEndpoint`` record with equivalent data in XDR field format.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of ``endpoint_id`` strings.
    """
    s1_agents = agent_repo.list_all()
    endpoint_ids: list[str] = []

    for index, agent in enumerate(s1_agents):
        eid = xdr_id("EP")
        endpoint_ids.append(eid)

        # Map OS type
        os_type = _OS_TYPE_MAP.get(agent.osType, "windows")

        # Map machine type
        machine_type = agent.machineType.lower() if agent.machineType else "desktop"
        endpoint_type = _ENDPOINT_TYPE_MAP.get(machine_type, "desktop")

        # Collect IPs from network interfaces
        ips: list[str] = []
        for iface in agent.networkInterfaces:
            for ip in iface.get("inet", []):
                ips.append(ip)
        if not ips:
            ips = [fake.ipv4_private()]

        # Build users list
        user_count = random.randint(1, 3)
        users = [fake.user_name() for _ in range(user_count)]

        # Group names
        group_names = [agent.groupName] if agent.groupName else []

        xdr_endpoint_repo.save(XdrEndpoint(
            endpoint_id=eid,
            endpoint_name=agent.computerName,
            endpoint_type=endpoint_type,
            endpoint_status=random.choice(XDR_ENDPOINT_STATUSES),
            os_type=os_type,
            ip=ips,
            domain="ACMECORP",
            alias=agent.computerName.lower(),
            first_seen=rand_epoch_ms(180),
            last_seen=rand_epoch_ms(3),
            install_date=rand_epoch_ms(365),
            content_version=random.choice(XDR_CONTENT_VERSIONS),
            endpoint_version=random.choice(XDR_AGENT_VERSIONS),
            is_isolated=XDR_ISOLATION[index % len(XDR_ISOLATION)],
            isolated_date=None,
            group_name=group_names,
            operational_status=XDR_OPERATIONAL[index % len(XDR_OPERATIONAL)],
            scan_status=XDR_SCAN_STATES[index % len(XDR_SCAN_STATES)],
            users=users,
            installation_package=XDR_INSTALL_PACKAGES[
                index % len(XDR_INSTALL_PACKAGES)],
            public_ip=[fake.ipv4_public()],
        ))

    return endpoint_ids
