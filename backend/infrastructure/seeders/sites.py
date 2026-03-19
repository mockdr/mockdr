"""Sites seeder — seeds three sites and their default policies."""
import random
import uuid

from faker import Faker

from domain.site import Site
from infrastructure.seeders._shared import ago, make_policy, rand_ago
from repository.policy_repo import policy_repo
from repository.site_repo import site_repo
from utils.id_gen import new_id

_SITE_DEFS: list[tuple[str, str]] = [
    ("Workstations", "New York"),
    ("Servers", "Global"),
    ("Cloud Infrastructure", "AWS US-East"),
]


def seed_sites(fake: Faker, account_id: str, account_name: str) -> list[str]:
    """Create the three preset sites and attach a default policy to each.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        account_id: ID of the parent account.
        account_name: Display name of the parent account.

    Returns:
        List of site IDs in definition order.
    """
    site_ids: list[str] = []

    for i, (site_name, location) in enumerate(_SITE_DEFS):
        sid = new_id()
        site_ids.append(sid)
        total_lic = 500
        active_lic = random.randint(50, 200)
        site_repo.save(Site(
            id=sid,
            name=site_name,
            accountId=account_id,
            accountName=account_name,
            state="active",
            activeLicenses=active_lic,
            totalLicenses=total_lic,
            createdAt=ago(days=300),
            updatedAt=rand_ago(30),
            description=f"Site for {location}",
            registrationToken=str(uuid.uuid4()),
            siteType="Paid",
            sku="Complete",
            suite="Complete",
            healthStatus=True,
            isDefault=(i == 0),
            expiration=ago(days=-365),
            unlimitedExpiration=False,
            unlimitedLicenses=False,
            externalId=None,
            inheritAccountExpiration=None,
            irFields=None,
            usageType=None,
            creator=None,
            creatorId=None,
            licenses={
                "bundles": [{
                    "displayName": "Endpoint Security - Complete",
                    "majorVersion": 1,
                    "minorVersion": 33,
                    "name": "complete",
                    "surfaces": [{"count": total_lic, "name": "Total Agents"}],
                    "totalSurfaces": total_lic,
                }],
                "modules": [{
                    "displayName": "Remote Script Orchestration",
                    "majorVersion": 1,
                    "name": "rso",
                }],
                "settings": [{
                    "displayName": "90 Days",
                    "groupName": "dv_retention",
                    "setting": "90 Days",
                    "settingGroup": "dv_retention",
                    "settingGroupDisplayName": "Deep Visibility Data Retention",
                }],
            },
            # internal
            location=location,
        ))
        policy_repo.save_for_site(sid, make_policy(sid, "site"))

    return site_ids
