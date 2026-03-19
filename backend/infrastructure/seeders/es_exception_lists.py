"""Elastic Security exception lists seeder."""
from __future__ import annotations

import random

from faker import Faker

from domain.es_exception_item import EsExceptionItem
from domain.es_exception_list import EsExceptionList
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.es_shared import es_uuid
from repository.es_exception_item_repo import es_exception_item_repo
from repository.es_exception_list_repo import es_exception_list_repo

_EXCEPTION_LISTS: list[dict[str, str]] = [
    {
        "name": "Trusted Security Scanners",
        "description": "Exclude known vulnerability scanner processes.",
        "type": "detection",
    },
    {
        "name": "IT Admin Tools",
        "description": "Exclude legitimate IT administration tools.",
        "type": "detection",
    },
    {
        "name": "Development Build Servers",
        "description": "Exclude CI/CD build server processes.",
        "type": "detection",
    },
    {
        "name": "Endpoint Trusted Applications",
        "description": "Endpoint-level application allowlist.",
        "type": "endpoint",
    },
    {
        "name": "Endpoint Backup Agents",
        "description": "Exclude backup agent processes from endpoint protection.",
        "type": "endpoint",
    },
]

_EXCEPTION_ITEMS: list[list[dict]] = [
    # Trusted Security Scanners
    [
        {"name": "Nessus Scanner", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "/opt/nessus/sbin/nessusd"},
        ]},
        {"name": "Qualys Agent", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "C:\\Program Files\\Qualys\\QualysAgent\\QualysAgent.exe"},
        ]},
        {"name": "Nmap Scanner", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "/usr/bin/nmap"},
        ]},
    ],
    # IT Admin Tools
    [
        {"name": "PsExec Remote Admin", "entries": [
            {"field": "process.name", "operator": "is", "type": "match", "value": "psexec.exe"},
            {"field": "process.parent.name", "operator": "is", "type": "match", "value": "cmd.exe"},
        ]},
        {"name": "SCCM Client", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "C:\\Windows\\CCM\\CcmExec.exe"},
        ]},
    ],
    # Development Build Servers
    [
        {"name": "Jenkins Build Agent", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "/opt/jenkins/agent.jar"},
        ]},
        {"name": "GitHub Actions Runner", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "/opt/actions-runner/run.sh"},
        ]},
        {"name": "Docker Build Process", "entries": [
            {"field": "process.name", "operator": "is", "type": "match", "value": "dockerd"},
        ]},
        {"name": "Maven Build", "entries": [
            {"field": "process.name", "operator": "is", "type": "match", "value": "mvn"},
        ]},
    ],
    # Endpoint Trusted Applications
    [
        {"name": "CrowdStrike Falcon", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "C:\\Program Files\\CrowdStrike\\CSFalconService.exe"},
        ]},
        {"name": "Carbon Black Agent", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "C:\\Program Files\\Confer\\RepMgr.exe"},
        ]},
    ],
    # Endpoint Backup Agents
    [
        {"name": "Veeam Backup Agent", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "C:\\Program Files\\Veeam\\Endpoint Backup\\VeeamAgent.exe"},
        ]},
        {"name": "Commvault Agent", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "/opt/commvault/Base/cvd"},
        ]},
        {"name": "Veritas NetBackup", "entries": [
            {"field": "process.executable", "operator": "is", "type": "match", "value": "/usr/openv/netbackup/bin/bpcd"},
        ]},
    ],
]

_OS_TYPE_MAP: dict[str, list[str]] = {
    "detection": ["windows", "linux", "macos"],
    "endpoint": ["windows", "linux"],
}


def seed_es_exception_lists(fake: Faker, rule_ids: list[str]) -> None:
    """Generate 5 exception lists with 2-4 items each.

    Creates 3 detection-type and 2 endpoint-type exception lists with
    realistic exception entries.

    Args:
        fake:     Shared Faker instance (seeded externally).
        rule_ids: List of rule ID strings (available for linking).
    """
    created_by = "elastic"
    now_ts = rand_ago(0)

    for i, list_def in enumerate(_EXCEPTION_LISTS):
        list_id = es_uuid()
        list_slug = list_def["name"].lower().replace(" ", "-")
        list_type = list_def["type"]
        os_types = _OS_TYPE_MAP.get(list_type, ["windows"])

        es_exception_list_repo.save(EsExceptionList(
            id=list_id,
            list_id=list_slug,
            name=list_def["name"],
            description=list_def["description"],
            type=list_type,
            namespace_type="single",
            tags=[list_type, "acmecorp"],
            os_types=os_types,
            created_at=rand_ago(random.randint(30, 90)),
            created_by=created_by,
            updated_at=now_ts,
            updated_by=created_by,
            version=random.randint(1, 5),
        ))

        # Generate items for this list
        items = _EXCEPTION_ITEMS[i] if i < len(_EXCEPTION_ITEMS) else []
        for item_def in items:
            item_id = es_uuid()
            item_slug = item_def["name"].lower().replace(" ", "-")

            es_exception_item_repo.save(EsExceptionItem(
                id=item_id,
                item_id=item_slug,
                list_id=list_slug,
                name=item_def["name"],
                description=f"Exception for {item_def['name']}.",
                type="simple",
                namespace_type="single",
                entries=item_def["entries"],
                os_types=os_types,
                tags=[list_type],
                created_at=rand_ago(random.randint(7, 60)),
                created_by=created_by,
                updated_at=now_ts,
                updated_by=created_by,
            ))
