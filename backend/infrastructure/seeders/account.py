"""Account seeder — seeds the single top-level account record."""
from faker import Faker

from config import SEED_COUNT_AGENTS
from domain.account import Account
from infrastructure.seeders._shared import ago
from infrastructure.seeders.sites import SITE_COUNT, SITE_TOTAL_LICENSES
from infrastructure.seeders.users import SEED_USER_COUNT
from repository.account_repo import account_repo
from utils.id_gen import new_id

_ACCOUNT_NAME = "Acme Corp Security"


def seed_account(fake: Faker) -> tuple[str, str]:
    """Create the single account record and persist it.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).

    Returns:
        Tuple of ``(account_id, account_name)``.
    """
    account_id = new_id()
    account_repo.save(Account(
        id=account_id,
        name=_ACCOUNT_NAME,
        createdAt=ago(days=365),
        updatedAt=ago(days=1),
        state="active",
        numberOfSites=SITE_COUNT,
        numberOfAgents=SEED_COUNT_AGENTS,
        activeAgents=SEED_COUNT_AGENTS,
        numberOfUsers=SEED_USER_COUNT,
        accountType="Trial",
        isDefault=True,
        billingMode="subscription",
        usageType="customer",
        totalLicenses=SITE_COUNT * SITE_TOTAL_LICENSES,
        # An account expires, and a trial one demonstrably so.
        expiration=ago(days=-180),
        # The same document each site carries, summed to the account. It was
        # absent entirely, so `?module=` and `?sku=` matched no account and
        # a console reading the account's entitlements read nothing.
        licenses={
            "bundles": [{
                "displayName": "Endpoint Security - Complete",
                "majorVersion": 1,
                "minorVersion": 33,
                "name": "complete",
                "surfaces": [{
                    "count": SITE_COUNT * SITE_TOTAL_LICENSES,
                    "name": "Total Agents",
                }],
                "totalSurfaces": SITE_COUNT * SITE_TOTAL_LICENSES,
            }],
            "modules": [
                {"displayName": "Remote Script Orchestration", "majorVersion": 1,
                 "name": "rso"},
                {"displayName": "Deep Visibility", "majorVersion": 1, "name": "dv"},
            ],
            "settings": [{
                "displayName": "90 Days",
                "groupName": "dv_retention",
                "setting": "90 Days",
                "settingGroup": "dv_retention",
                "settingGroupDisplayName": "Deep Visibility Data Retention",
            }],
        },
        # The swagger's enum is capitalised: Core, Control, Complete.
        skus=[{"type": "Complete",
               "totalLicenses": SITE_COUNT * SITE_TOTAL_LICENSES}],
    ))
    return account_id, _ACCOUNT_NAME
