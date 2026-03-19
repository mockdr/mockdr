"""XDR audit logs seeder -- generates management audit log entries."""
from __future__ import annotations

import random

from faker import Faker

from domain.xdr_audit_log import XdrAuditLog
from infrastructure.seeders.xdr_shared import XDR_AUDIT_SUB_TYPES, rand_epoch_ms, xdr_id
from repository.xdr_audit_log_repo import xdr_audit_log_repo

_RESULTS: list[str] = ["SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "FAILURE"]

_DESCRIPTIONS: dict[str, list[str]] = {
    "Login": ["User logged in via SAML SSO", "User logged in via credentials"],
    "Logout": ["User logged out", "Session expired"],
    "Policy Change": ["Malware protection policy updated", "Exploit protection policy modified"],
    "Incident Update": ["Incident status changed to resolved", "Incident assigned to analyst"],
    "Alert Update": ["Alert severity changed", "Alert excluded from policy"],
    "Endpoint Isolation": ["Endpoint isolated for investigation"],
    "Endpoint Unisolation": ["Endpoint restored to network"],
    "Script Execution": ["Script executed on endpoint", "Bulk script execution initiated"],
    "IOC Created": ["New hash IOC added", "New IP IOC added"],
    "IOC Deleted": ["Expired IOC removed"],
    "Distribution Created": ["New agent distribution package created"],
    "User Role Change": ["User role changed from viewer to analyst"],
}


def seed_xdr_audit_logs(fake: Faker) -> None:
    """Seed ~30 XDR management audit log entries.

    Args:
        fake: Shared Faker instance (seeded externally).
    """
    count = 30

    for _ in range(count):
        sub_type = random.choice(XDR_AUDIT_SUB_TYPES)
        user_name = fake.name()
        descriptions = _DESCRIPTIONS.get(sub_type, [f"{sub_type} action performed"])

        xdr_audit_log_repo.save(XdrAuditLog(
            audit_id=xdr_id("AUD"),
            sub_type=sub_type,
            result=random.choice(_RESULTS),
            timestamp=rand_epoch_ms(90),
            user_name=user_name,
            user_email=f"{user_name.lower().replace(' ', '.')}@acmecorp.internal",
            description=random.choice(descriptions),
            host_name=fake.hostname() if sub_type in {"Endpoint Isolation", "Endpoint Unisolation", "Script Execution"} else "",
        ))
