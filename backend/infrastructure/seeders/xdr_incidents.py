"""XDR incidents seeder -- generates realistic incident records."""
from __future__ import annotations

import random

from faker import Faker

from domain.xdr_incident import XdrIncident
from infrastructure.seeders.xdr_shared import (
    XDR_ALERT_SOURCES,
    XDR_INCIDENT_DESCRIPTIONS,
    XDR_INCIDENT_STATUSES,
    XDR_SEVERITIES,
    rand_epoch_ms,
    xdr_id,
)
from repository.xdr_endpoint_repo import xdr_endpoint_repo
from repository.xdr_incident_repo import xdr_incident_repo


def seed_xdr_incidents(fake: Faker, endpoint_ids: list[str]) -> list[str]:
    """Generate ~20 XDR incident records linked to endpoints.

    Args:
        fake: Shared Faker instance (seeded externally).
        endpoint_ids: Available endpoint IDs to link incidents to.

    Returns:
        List of ``incident_id`` strings.
    """
    incident_ids: list[str] = []
    count = 20

    for i in range(count):
        iid = xdr_id("INC")
        incident_ids.append(iid)

        severity = random.choice(XDR_SEVERITIES)
        status = random.choice(XDR_INCIDENT_STATUSES)
        creation = rand_epoch_ms(60)

        # Pick random hosts for this incident
        host_count = random.randint(1, min(4, len(endpoint_ids)))
        host_ids = random.sample(endpoint_ids, host_count)
        host_names: list[str] = []
        for eid in host_ids:
            ep = xdr_endpoint_repo.get(eid)
            if ep:
                host_names.append(ep.endpoint_name)

        # Pick random users
        user_count = random.randint(1, 3)
        users = [fake.user_name() for _ in range(user_count)]

        # Alert count breakdown
        total_alerts = random.randint(1, 8)
        low_alerts = random.randint(0, total_alerts // 3)
        high_alerts = random.randint(0, total_alerts // 3)
        med_alerts = total_alerts - low_alerts - high_alerts

        # Assigned user for non-new incidents
        assigned_mail = ""
        assigned_name = ""
        if status != "new":
            assigned_name = fake.name()
            assigned_mail = f"{assigned_name.lower().replace(' ', '.')}@acmecorp.internal"

        xdr_incident_repo.save(XdrIncident(
            incident_id=iid,
            description=XDR_INCIDENT_DESCRIPTIONS[i % len(XDR_INCIDENT_DESCRIPTIONS)],
            alert_count=total_alerts,
            severity=severity,
            status=status,
            assigned_user_mail=assigned_mail,
            assigned_user_pretty_name=assigned_name,
            creation_time=creation,
            modification_time=rand_epoch_ms(30),
            detection_time=str(creation),
            low_severity_alert_count=low_alerts,
            med_severity_alert_count=med_alerts,
            high_severity_alert_count=high_alerts,
            hosts=host_names,
            users=users,
            incident_sources=random.sample(
                XDR_ALERT_SOURCES,
                k=min(len(XDR_ALERT_SOURCES), random.randint(1, 3)),
            ),
            rule_based_score=random.randint(0, 100),
            manual_score=random.choice([0, 0, 0, random.randint(1, 100)]),
        ))

    return incident_ids
