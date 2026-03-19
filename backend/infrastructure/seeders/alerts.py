"""Alerts seeder — seeds the configured number of STAR rule alert records."""
import random

from faker import Faker

from config import SEED_COUNT_ALERTS
from domain.alert import Alert
from infrastructure.process_gen import PROCESS_CATALOG
from infrastructure.seeders._shared import (
    ALERT_INCIDENT_STATUSES,
    ALERT_SEVERITIES,
    ALERT_VERDICTS,
    MITRE_TACTICS,
    rand_ago,
)
from repository.agent_repo import agent_repo
from repository.alert_repo import alert_repo
from utils.id_gen import new_id


def seed_alerts(fake: Faker, agent_ids: list[str]) -> None:
    """Create ``SEED_COUNT_ALERTS`` alert records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        agent_ids: Pool of agent IDs to randomly associate alerts with.
    """
    for _ in range(SEED_COUNT_ALERTS):
        alid = new_id()
        rule_id = new_id()
        agent = agent_repo.get(random.choice(agent_ids))
        assert agent is not None
        proc_name, proc_path = random.choice(PROCESS_CATALOG)
        created = rand_ago(30)
        updated = rand_ago(5)
        severity = random.choice(ALERT_SEVERITIES)
        category = random.choice(["Threat Intelligence", "Behavioral", "Network", "Endpoint"])
        tactic = random.choice(MITRE_TACTICS)

        alert_repo.save(Alert(
            alertInfo={
                "alertId": alid,
                "eventType": random.choice(["Process", "File", "Network", "Registry"]),
                "createdAt": created,
                "updatedAt": updated,
                "analystVerdict": random.choice(ALERT_VERDICTS),
                "incidentStatus": random.choice(ALERT_INCIDENT_STATUSES),
                "dvEventId": new_id(),
                "hitType": "Events",
                "reportedAt": created,
                "source": "STAR",
                "isEdr": True,
                "srcIp": None, "dstIp": None, "srcPort": None, "dstPort": None,
                "srcMachineIp": None, "netEventDirection": None,
                "dnsRequest": None, "dnsResponse": None,
                "registryKeyPath": None, "registryPath": None,
                "registryValue": None, "registryOldValue": None,
                "registryOldValueType": None,
                "modulePath": None, "moduleSha1": None,
                "loginAccountDomain": None, "loginAccountSid": None,
                "loginIsSuccessful": None, "loginIsAdministratorEquivalent": None,
                "loginType": None, "loginsUserName": None,
                "indicatorName": None, "indicatorCategory": None,
                "indicatorDescription": None,
                "tiIndicatorType": None, "tiIndicatorSource": None,
                "tiIndicatorComparisonMethod": None, "tiIndicatorValue": None,
            },
            ruleInfo={
                "id": rule_id,
                "name": f"STAR Rule: {fake.bs().title()}",
                "severity": severity,
                "description": f"Detects {category.lower()} activity via {tactic}",
                "queryType": "events",
                "queryLang": "1.0",
                "scopeLevel": "site",
                "s1ql": f'EventType = "Process" AND TgtProcName Contains "{proc_name}"',
                "treatAsThreat": "UNDEFINED",
            },
            sourceProcessInfo={
                "name": proc_name,
                "filePath": proc_path,
                "user": f"ACMECORP\\{fake.user_name()}",
                "commandline": f"{proc_path} {fake.word()}",
                "fileHashSha1": fake.sha1(),
                "fileHashSha256": fake.sha256(),
                "fileHashMd5": fake.md5(),
                "pidStarttime": f"{random.randint(1000, 65535)}-{rand_ago(1)}",
                "pid": str(random.randint(1000, 65535)),
                "storyline": new_id(),
                "uniqueId": new_id(),
                "integrityLevel": random.choice(["medium", "high", "system"]),
                "subsystem": "sys_win32",
                "effectiveUser": None, "realUser": None,
                "loginUser": None, "fileSignerIdentity": None,
            },
            agentDetectionInfo={
                "uuid": agent.uuid,
                "name": agent.computerName,
                "version": agent.agentVersion,
                "siteId": agent.siteId,
                "accountId": agent.accountId,
                "machineType": agent.machineType,
                "osName": agent.osName,
                "osFamily": agent.osType,
                "osRevision": agent.osRevision,
            },
            agentRealtimeInfo={
                "id": agent.uuid,
                "agentComputerName": agent.computerName,
                "os": agent.osType,
                "agentVersion": agent.agentVersion,
                "siteId": agent.siteId,
                "siteName": agent.siteName,
                "accountId": agent.accountId,
            },
        ))
