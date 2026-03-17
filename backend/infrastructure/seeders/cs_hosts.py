"""CrowdStrike hosts seeder — maps existing S1 agents to CS host records."""
from __future__ import annotations

import random

from faker import Faker

from domain.cs_host import CsHost
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.cs_shared import CS_CID, cs_hex_id
from repository.agent_repo import agent_repo
from repository.cs_host_repo import cs_host_repo
from repository.store import store

_PLATFORM_MAP: dict[str, str] = {
    "windows": "Windows",
    "macos": "Mac",
    "linux": "Linux",
}

_PLATFORM_ID_MAP: dict[str, str] = {
    "windows": "0",
    "macos": "1",
    "linux": "2",
}

_PRODUCT_TYPE_MAP: dict[str, str] = {
    "server": "Server",
    "laptop": "Workstation",
    "desktop": "Workstation",
}

_CHASSIS_TYPE_MAP: dict[str, str] = {
    "server": "Server",
    "laptop": "Laptop",
    "desktop": "Desktop",
}

_STATUS_CHOICES: list[str] = (
    ["normal"] * 17
    + ["contained"]
    + ["containment_pending"]
    + ["lift_containment_pending"]
)

_EXTRA_TAGS: list[str] = ["Production", "Development", "Staging", "Critical"]


def seed_cs_hosts(fake: Faker) -> list[str]:
    """Create CrowdStrike host records from existing S1 agent fleet.

    Reads every S1 agent from ``agent_repo`` and creates a corresponding
    ``CsHost`` record with equivalent data in CrowdStrike field format.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of ``device_id`` strings.
    """
    s1_agents = agent_repo.list_all()
    device_ids: list[str] = []

    for agent in s1_agents:
        device_id = cs_hex_id()
        device_ids.append(device_id)

        # Store agent↔device mapping for cross-EDR views
        mapping = store.get("edr_id_map", agent.id) or {}
        mapping["cs_device_id"] = device_id
        store.save("edr_id_map", agent.id, mapping)

        platform_name = _PLATFORM_MAP.get(agent.osType, "Windows")
        platform_id = _PLATFORM_ID_MAP.get(agent.osType, "0")
        product_type_desc = _PRODUCT_TYPE_MAP.get(agent.machineType, "Workstation")
        chassis_type = _CHASSIS_TYPE_MAP.get(agent.machineType, "Desktop")

        # Build network fields from first interface if available
        mac_address = ""
        if agent.networkInterfaces:
            iface = agent.networkInterfaces[0]
            mac_address = iface.get("physical", "")

        # Build sensor grouping tags
        extra_count = random.randint(0, 2)
        extra = random.sample(_EXTRA_TAGS, extra_count)
        tags = ["SensorGroupingTags/AcmeCorp"] + [
            f"SensorGroupingTags/{t}" for t in extra
        ]

        status = random.choice(_STATUS_CHOICES)
        now_ts = rand_ago(0)

        cs_host_repo.save(CsHost(
            device_id=device_id,
            cid=CS_CID,
            hostname=agent.computerName,
            local_ip=agent.lastIpToMgmt or (
                agent.networkInterfaces[0]["inet"][0]
                if agent.networkInterfaces
                else fake.ipv4_private()
            ),
            external_ip=agent.externalIp,
            mac_address=mac_address,
            connection_ip=agent.externalIp,
            os_version=agent.osName,
            os_build=agent.osRevision,
            platform_name=platform_name,
            platform_id=platform_id,
            kernel_version="",
            major_version="",
            minor_version="",
            build_number=agent.osRevision,
            system_manufacturer=agent.modelName.split(" ")[0] if agent.modelName else "",
            system_product_name=agent.modelName,
            bios_manufacturer=agent.modelName.split(" ")[0] if agent.modelName else "",
            bios_version=fake.lexify("?.##.####"),
            serial_number=agent.serialNumber,
            chassis_type=chassis_type,
            chassis_type_desc=chassis_type,
            pointer_size="8",
            cpu_signature=agent.cpuId,
            agent_version=agent.agentVersion,
            agent_load_flags="0",
            config_id_base=str(random.randint(60000000, 69999999)),
            config_id_build=str(random.randint(10000, 20000)),
            config_id_platform=platform_id,
            reduced_functionality_mode="no",
            provision_status="Provisioned",
            status=status,
            first_seen=agent.createdAt,
            last_seen=agent.lastActiveDate,
            modified_timestamp=now_ts,
            slow_changing_modified_timestamp=rand_ago(7),
            site_name=agent.siteName,
            machine_domain=agent.domain,
            ou=[],
            email="",
            product_type_desc=product_type_desc,
            service_provider="",
            service_provider_account_id="",
            detection_suppression_status="active",
            tags=tags,
            groups=[],  # populated by host group seeder
            policies=[{
                "policy_type": "prevention",
                "policy_id": cs_hex_id(),
                "applied": True,
                "settings_hash": fake.sha256()[:16],
                "assigned_date": agent.createdAt,
                "applied_date": agent.createdAt,
                "rule_groups": [],
            }],
            device_policies={
                "prevention": {
                    "policy_type": "prevention",
                    "policy_id": cs_hex_id(),
                    "applied": True,
                    "settings_hash": fake.sha256()[:16],
                    "assigned_date": agent.createdAt,
                    "applied_date": agent.createdAt,
                    "rule_groups": [],
                },
                "sensor_update": {
                    "policy_type": "sensor_update",
                    "policy_id": cs_hex_id(),
                    "applied": True,
                    "settings_hash": fake.sha256()[:16],
                    "assigned_date": agent.createdAt,
                    "applied_date": agent.createdAt,
                    "uninstall_protection": "ENABLED",
                },
            },
            meta={"version": "1"},
        ))

    return device_ids
