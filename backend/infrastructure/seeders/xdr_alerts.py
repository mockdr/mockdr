"""XDR alerts seeder -- generates realistic alert records linked to incidents."""
from __future__ import annotations

import random

from faker import Faker

from domain.xdr_alert import XdrAlert
from infrastructure.seeders.xdr_shared import (
    XDR_ALERT_ACTIONS,
    XDR_ALERT_CATEGORIES,
    XDR_ALERT_NAMES,
    XDR_ALERT_SOURCES,
    XDR_MITRE_TACTICS,
    XDR_MITRE_TECHNIQUES,
    XDR_SEVERITIES,
    rand_epoch_ms,
    xdr_id,
)
from repository.xdr_alert_repo import xdr_alert_repo
from repository.xdr_endpoint_repo import xdr_endpoint_repo

_EVENT_TYPES: list[str] = [
    "Process Execution", "File Creation", "Network Connection",
    "Registry Modification", "Injection", "Load Image",
]


def seed_xdr_alerts(
    fake: Faker,
    incident_ids: list[str],
    endpoint_ids: list[str],
) -> None:
    """Generate ~40 XDR alert records linked to incidents and endpoints.

    Args:
        fake: Shared Faker instance (seeded externally).
        incident_ids: Available incident IDs to link alerts to.
        endpoint_ids: Available endpoint IDs to link alerts to.
    """
    count = 40

    for _ in range(count):
        aid = xdr_id("ALR")
        severity = random.choice(XDR_SEVERITIES)
        action = random.choice(XDR_ALERT_ACTIONS)
        action_pretty_map = {
            "detected": "Detected (Post Detected)",
            "prevented": "Prevented (Blocked)",
            "blocked": "Blocked",
        }

        # Link to a random incident
        incident_id = random.choice(incident_ids)

        # Link to a random endpoint
        eid = random.choice(endpoint_ids)
        ep = xdr_endpoint_repo.get(eid)
        host_name = ep.endpoint_name if ep else fake.hostname()
        host_ips = ep.ip if ep else [fake.ipv4_private()]

        xdr_alert_repo.save(XdrAlert(
            alert_id=aid,
            internal_id=xdr_id("INT"),
            severity=severity,
            category=random.choice(XDR_ALERT_CATEGORIES),
            action=action,
            action_pretty=action_pretty_map.get(action, action),
            description=f"Alert triggered by {random.choice(XDR_ALERT_SOURCES)} on {host_name}",
            name=random.choice(XDR_ALERT_NAMES),
            source=random.choice(XDR_ALERT_SOURCES),
            detection_timestamp=rand_epoch_ms(60),
            endpoint_id=eid,
            host_name=host_name,
            host_ip=host_ips,
            user_name=fake.user_name(),
            mitre_technique_id_and_name=random.choice(XDR_MITRE_TECHNIQUES),
            mitre_tactic_id_and_name=random.choice(XDR_MITRE_TACTICS),
            starred=random.random() < 0.1,
            event_type=random.choice(_EVENT_TYPES),
            is_whitelisted=False,
            alert_action_status=action,
            incident_id=incident_id,
        ))
