"""Agents seeder — seeds the configured number of endpoint agents."""
import random
import uuid

from faker import Faker

from config import SEED_COUNT_AGENTS
from domain.agent import Agent
from infrastructure.seeders._shared import (
    _AD_DOMAIN,
    AD_GROUPS_POOL,
    AD_OUS,
    CPU_MODELS,
    MACHINE_MODELS,
    OS_VARIANTS,
    USER_AD_GROUPS_POOL,
    passphrase,
    rand_ago,
)
from repository.agent_repo import agent_repo
from repository.group_repo import group_repo
from repository.site_repo import site_repo
from repository.tag_repo import tag_repo
from utils.id_gen import new_id


def seed_agents(
    fake: Faker,
    account_id: str,
    account_name: str,
    group_ids_by_site: dict[str, list[str]],
) -> list[str]:
    """Create ``SEED_COUNT_AGENTS`` agent records and persist them.

    Also increments ``Group.totalAgents`` for every group an agent is
    placed into.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        account_id: ID of the parent account.
        account_name: Display name of the parent account.
        group_ids_by_site: Mapping of ``site_id → [group_id, ...]`` as
            returned by :func:`infrastructure.seeders.groups.seed_groups`.

    Returns:
        List of agent IDs.
    """
    all_group_site_pairs: list[tuple[str, str]] = [
        (gid, sid)
        for sid, gids in group_ids_by_site.items()
        for gid in gids
    ]

    agent_ids: list[str] = []

    for _ in range(SEED_COUNT_AGENTS):
        aid = new_id()
        agent_ids.append(aid)

        gid, sid = random.choice(all_group_site_pairs)
        group = group_repo.get(gid)
        assert group is not None
        site = site_repo.get(sid)
        assert site is not None
        os_name, os_type, os_rev, agent_ver = random.choice(OS_VARIANTS)

        prefix_choices = {
            "windows": ["DESKTOP", "LAPTOP", "WKSTN", "SERVER"],
            "macos": ["MAC"],
            "linux": ["UBUNTU", "RHEL", "SRV"],
        }
        prefix = random.choice(prefix_choices[os_type])
        hostname = f"{prefix}-{fake.lexify('??????').upper()}"
        machine_type = (
            "server" if prefix in ("SERVER", "RHEL", "SRV", "UBUNTU")
            else "laptop" if prefix == "LAPTOP"
            else "desktop"
        )

        is_active = random.random() > 0.15
        is_infected = random.random() < 0.08
        registered_at = rand_ago(200)

        scan_started: str | None
        scan_finished: str | None
        scan_aborted: str | None
        scan_roll = random.random()
        if scan_roll > 0.3:
            scan_started = rand_ago(7)
            scan_outcome = random.choice(["finished", "finished", "aborted"])
            # Derive finish/abort time relative to scan start so it is always later
            from datetime import UTC as _UTC
            from datetime import datetime, timedelta
            _start_dt = datetime.strptime(scan_started, "%Y-%m-%dT%H:%M:%S.000Z").replace(tzinfo=_UTC)
            _end_dt = _start_dt + timedelta(minutes=random.randint(5, 120))
            _end_ts = _end_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
            scan_finished = _end_ts if scan_outcome == "finished" else None
            scan_aborted = _end_ts if scan_outcome == "aborted" else None
        else:
            scan_started = None
            scan_finished = None
            scan_aborted = None
            scan_outcome = "none"

        local_ip = fake.ipv4_private()
        ext_ip = fake.ipv4_public()
        ext_ip_prefix = ".".join(ext_ip.split(".")[:3])
        iface_name = "Ethernet0" if os_type == "windows" else "eth0"
        mac_addr = fake.mac_address()
        gw_mac = fake.mac_address()
        network_interfaces = [{
            "gatewayIp": fake.ipv4_private(),
            "gatewayMacAddress": gw_mac,
            "id": new_id(),
            "inet": [local_ip],
            "inet6": [
                f"fe80::{fake.lexify('????')}:{fake.lexify('????')}"
                f":{fake.lexify('????')}:{fake.lexify('????')}"
            ],
            "name": iface_name,
            "physical": mac_addr,
        }]

        # Assign tags by referencing tag definitions whose scope applies
        all_tags = tag_repo.list_all()
        applicable = [
            t for t in all_tags
            if t.scopeLevel == "global"
            or (t.scopeLevel == "account" and t.scopeId == account_id)
            or (t.scopeLevel == "site" and t.scopeId == sid)
            or (t.scopeLevel == "group" and t.scopeId == gid)
        ]
        tag_count = random.randint(0, min(2, len(applicable)))
        s1_tags = []
        if tag_count > 0:
            for tag_def in random.sample(applicable, tag_count):
                s1_tags.append({
                    "assignedAt": rand_ago(30),
                    "assignedBy": random.choice([
                        "SVC-JUPYTER", "admin@corp.com", "automation",
                    ]),
                    "assignedById": new_id(),
                    "id": tag_def.id,
                    "key": tag_def.key,
                    "value": tag_def.value,
                })

        if os_type == "windows":
            computer_ou = random.choice(AD_OUS)
            computer_cn = f"CN={hostname},{computer_ou}"
            last_user_id = fake.lexify("????????").upper()
            last_user_dn = f"CN={last_user_id},OU=Users,OU=Global,{_AD_DOMAIN}"
            ad_info = {
                "computerDistinguishedName": computer_cn,
                "computerMemberOf": random.sample(
                    AD_GROUPS_POOL, random.randint(3, 8)
                ),
                "lastUserDistinguishedName": last_user_dn,
                "lastUserMemberOf": random.sample(
                    USER_AD_GROUPS_POOL, random.randint(3, 8)
                ),
                "userPrincipalName": f"{last_user_id.lower()}@acmecorp.internal",
            }
            last_logged_in = last_user_id
        else:
            ad_info = {}
            last_logged_in = fake.user_name()

        cpu_id = random.choice(CPU_MODELS)
        cpu_count = random.choice([1, 2, 2, 4])
        core_count = random.choice([2, 4, 4, 8, 16])
        total_memory = random.choice([4096, 8192, 8192, 16384, 32768])
        machine_sid = (
            f"S-1-5-21"
            f"-{random.randint(1000000000, 3999999999)}"
            f"-{random.randint(100000000, 999999999)}"
            f"-{random.randint(100000000, 999999999)}"
            f"-{random.randint(1000, 9999)}"
        )

        agent_repo.save(Agent(
            id=aid,
            uuid=str(uuid.uuid4()),
            computerName=hostname,
            externalId="",
            serialNumber=str(uuid.uuid4()).upper(),
            accountId=account_id,
            accountName=account_name,
            siteId=sid,
            siteName=site.name,
            groupId=gid,
            groupName=group.name,
            groupIp=f"{ext_ip_prefix}.x",
            osName=os_name,
            osType=os_type,
            osRevision=os_rev,
            osArch="64 bit",
            osUsername="root" if os_type == "linux" else None,
            osStartTime=rand_ago(random.randint(1, 30)),
            machineType=machine_type,
            modelName=random.choice(MACHINE_MODELS),
            machineSid=machine_sid,
            cpuId=cpu_id,
            cpuCount=cpu_count,
            coreCount=core_count,
            totalMemory=total_memory,
            agentVersion=agent_ver,
            installerType=(
                ".msi" if os_type == "windows"
                else ".pkg" if os_type == "macos"
                else ".deb"
            ),
            registeredAt=registered_at,
            createdAt=registered_at,
            updatedAt=rand_ago(1),
            groupUpdatedAt=rand_ago(30),
            lastActiveDate=rand_ago(5) if is_active else rand_ago(30),
            licenseKey="",
            isActive=is_active,
            isDecommissioned=False,
            isPendingUninstall=False,
            isUninstalled=False,
            isUpToDate=random.random() > 0.2,
            isAdConnector=False,
            isHyperAutomate=None,
            externalIp=ext_ip,
            lastIpToMgmt=local_ip,
            domain=fake.domain_name(),
            networkStatus=random.choice(
                ["connected"] * 7 + ["disconnected"] * 2 + ["disconnecting"]
            ),
            networkQuarantineEnabled=False,
            networkInterfaces=network_interfaces,
            locationEnabled=os_type != "linux",
            locationType=(
                random.choice(["fallback", "specific", "fallback"])
                if os_type != "linux" else "not_supported"
            ),
            locations=(
                [{"id": new_id(), "name": site.name, "scope": "site"}]
                if os_type != "linux" else []
            ),
            infected=is_infected,
            activeThreats=random.randint(0, 3) if is_infected else 0,
            detectionState="full_mode" if os_type != "linux" else "",
            mitigationMode=random.choice(["protect", "protect", "detect"]),
            mitigationModeSuspicious="detect",
            activeProtection=["edr"],
            threatRebootRequired=False,
            firewallEnabled=random.random() > 0.1,
            encryptedApplications=False,
            appsVulnerabilityStatus=random.choice(["not_applicable"] * 3 + ["patch_required"]),
            showAlertIcon=False,
            missingPermissions=[],
            userActionsNeeded=[],
            scanStatus=scan_outcome,
            scanFinishedAt=scan_finished,
            scanAbortedAt=scan_aborted,
            scanStartedAt=scan_started,
            lastSuccessfulScanDate=scan_finished,
            fullDiskScanLastUpdatedAt=scan_finished,
            firstFullModeTime=rand_ago(190),
            rangerStatus=random.choice(
                ["NotApplicable", "NotApplicable", "Enabled", "Disabled"]
            ),
            rangerVersion="21.11.0.171" if os_type != "linux" else "",
            allowRemoteShell=True,
            inRemoteShellSession=False,
            remoteProfilingState="disabled",
            remoteProfilingStateExpiration=None,
            proxyStates={"console": False, "deepVisibility": False},
            cloudProviders={},
            hasContainerizedWorkload=(
                os_type == "linux" and random.random() > 0.5
            ),
            containerizedWorkloadCounts=None,
            consoleMigrationStatus="N/A",
            operationalState="na",
            operationalStateExpiration=None,
            storageName=None,
            storageType=None,
            tags={"sentinelone": s1_tags},
            activeDirectory=ad_info,
            passphrase=passphrase(),
            lastLoggedInUserName=last_logged_in,
            localIp=local_ip,
            installedAt=registered_at,
            isInfected=is_infected,
            agentLicenseType="y3",
            cpuUsage=random.randint(1, 45),
            memoryUsage=random.randint(512, total_memory),
        ))

        # Keep group agent count in sync
        group.totalAgents += 1
        group_repo.save(group)

    # ── Decommissioned agents: mark ~5% of agents as decommissioned ──────
    decomm_count = max(3, len(agent_ids) // 20)
    for aid in agent_ids[-decomm_count:]:
        agent = agent_repo.get(aid)
        if agent:
            agent.isDecommissioned = True
            agent.isActive = False
            agent.networkStatus = "disconnected"
            agent.decommissionedAt = rand_ago(random.randint(3, 30))
            agent_repo.save(agent)

    return agent_ids
