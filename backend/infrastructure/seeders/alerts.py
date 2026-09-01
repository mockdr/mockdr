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
    rand_after,
    rand_ago,
)
from repository.agent_repo import agent_repo
from repository.alert_repo import alert_repo
from repository.store import store
from repository.user_repo import user_repo
from utils.id_gen import new_id

#: The swagger's own rule statuses; most rules in a console are live, so the
#: spread is weighted rather than uniform.
STAR_RULE_STATUSES: list[str] = ["Active", "Active", "Active", "Draft", "Disabled"]


def seed_alerts(fake: Faker, agent_ids: list[str]) -> None:
    """Create ``SEED_COUNT_ALERTS`` alert records and persist them.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        agent_ids: Pool of agent IDs to randomly associate alerts with.
    """
    # The rules below name their author; resolve the real record once so the
    # id they carry is one a client can look up.
    admin = next((u for u in user_repo.list_all() if u.fullName == "Admin User"), None)
    creator_name = admin.fullName if admin else "Admin User"
    creator_id = admin.id if admin else ""

    for index in range(SEED_COUNT_ALERTS):
        alid = new_id()
        rule_id = new_id()
        agent = agent_repo.get(random.choice(agent_ids))
        assert agent is not None
        proc_name, proc_path = random.choice(PROCESS_CATALOG)
        created = rand_ago(30)
        # Not a second independent draw: an alert updated before it was
        # created is one no console can put on a timeline.
        updated = rand_after(created, 5)
        severity = random.choice(ALERT_SEVERITIES)
        category = random.choice(["Threat Intelligence", "Behavioral", "Network", "Endpoint"])
        tactic = random.choice(MITRE_TACTICS)
        rule_name = f"STAR Rule: {fake.bs().title()}"
        rule_description = f"Detects {category.lower()} activity via {tactic}"
        rule_s1ql = f'EventType = "Process" AND TgtProcName Contains "{proc_name}"'

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
                "name": rule_name,
                "severity": severity,
                "description": rule_description,
                "queryType": "events",
                "queryLang": "1.0",
                "scopeLevel": "site",
                "s1ql": rule_s1ql,
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
                "id": agent.id,
                "agentComputerName": agent.computerName,
                "os": agent.osType,
                "agentVersion": agent.agentVersion,
                "siteId": agent.siteId,
                "siteName": agent.siteName,
                "accountId": agent.accountId,
            },
        ))

        # Every alert embeds a ruleInfo.id, but nothing was ever written to the
        # star_rules collection — so GET /cloud-detection/rules was empty and
        # each alert pointed at a rule that existed nowhere.
        store.save("star_rules", rule_id, {
            "id": rule_id,
            "name": rule_name,
            "description": rule_description,
            "queryType": "events",
            "queryLang": "1.0",
            "s1ql": rule_s1ql,
            "severity": severity,
            "scopeLevel": "site",
            # The scope's own id, which the swagger declares beside
            # `scopeLevel` and nothing set — so the documented `scopeId`
            # filter matched no rule.
            "scopeId": agent.siteId,
            "siteIds": [agent.siteId],
            "groupIds": [],
            "accountIds": [agent.accountId],
            # The swagger declares the rule's scope as three singular fields
            # and none of the plural ones above. Only the plurals were
            # written, so the answer carried the swagger's own example id —
            # the same one for all twenty rules — and the documented
            # `accountIds`, `siteIds` and `scopes` filters matched nothing.
            "scope": "site",
            "siteId": agent.siteId,
            "accountId": agent.accountId,
            "treatAsThreat": "UNDEFINED",
            # The swagger's own enum. Seeding only "Active" left the
            # documented status filter untestable and the console's rule list
            # uniform, which no console ever is.
            "status": STAR_RULE_STATUSES[index % len(STAR_RULE_STATUSES)],
            "expirationMode": "Permanent",
            "expiration": None,
            "networkQuarantine": False,
            "createdAt": created,
            "updatedAt": created,
            "creator": creator_name,
            # A user by this name exists in the store, and the rule pointed at
            # nobody: `creatorId` was empty, so the answer carried the
            # swagger's example id and a client resolving the rule's author
            # found no such user. `updatedAt` equals `createdAt` here — the
            # rule has never been changed since — so its last updater is the
            # one who made it.
            "creatorId": creator_id,
            # `updater` itself is declared as a null schema, so the answer
            # carries null there whatever is stored; only the id is a field.
            "updaterId": creator_id,
            # Every seeded rule has exactly one alert, and the answer said it
            # had none and had last fired in 2018 — the swagger's example
            # date, in an estate seeded around today.
            "generatedAlerts": 1,
            "lastAlertTime": created,
        })
