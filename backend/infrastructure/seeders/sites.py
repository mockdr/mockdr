"""Sites seeder — seeds three sites and their default policies."""

from faker import Faker

from domain.site import Site
from infrastructure.seeders._shared import ago, make_policy, rand_ago
from repository.policy_repo import policy_repo
from repository.site_repo import site_repo
from utils.id_gen import new_id, new_uuid

#: Licences each seeded site carries. The account's `totalLicenses` is
#: "the total number of licenses on all Surfaces for all Bundles", so it is
#: this times the number of sites — it answered 0 while three sites held 500
#: each, and nothing could filter by the number it did answer.
SITE_TOTAL_LICENSES = 500

_SITE_DEFS: list[tuple[str, str]] = [
    ("Workstations", "New York"),
    ("Servers", "Global"),
    ("Cloud Infrastructure", "AWS US-East"),
]

#: How many sites a seeded account has.
SITE_COUNT = len(_SITE_DEFS)


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
        total_lic = SITE_TOTAL_LICENSES
        # Counted from the agents on the way out (see
        # `application/sites/queries.py`), because agents are seeded after the
        # sites they belong to. A random 50-200 here had a site of 18 agents
        # answering 76 active licences, and the number never moved.
        active_lic = 0
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
            registrationToken=str(new_uuid()),
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

    # The account-wide policy every site and group inherits from. Without it
    # `/tenant/policy` and `/accounts/{id}/policy` answered a 200 with a null
    # body, which reads as "this install has no policy" rather than as the
    # document a console shows.
    policy_repo.save_for_tenant(make_policy(account_id, "account"))

    return site_ids


def resync_site_licences() -> None:
    """Set each site's `activeLicenses` to the agents installed on it.

    "Number of active licenses for the site", and the licence surface each
    site answers beside it is named `Total Agents` with a count equal to
    `totalLicenses` — so the unit is an agent and an active licence is an
    agent using one. The seeder drew a random 50-200 instead, and a site
    holding 18 agents answered 76.

    It is stored rather than counted on the way out, because the documented
    `activeLicenses` filter and sort read the record: computing it in the
    query made `?activeLicenses=18` and `?sortBy=activeLicenses` disagree
    with the answer, which is the defect this repo spent the day removing.
    Agents are seeded after their sites, so this runs once both exist.
    """
    from repository.agent_repo import agent_repo

    counts: dict[str, int] = {}
    for agent in agent_repo.list_all():
        site_id = str(getattr(agent, "siteId", "") or "")
        if site_id:
            counts[site_id] = counts.get(site_id, 0) + 1
    for site in site_repo.list_all():
        site.activeLicenses = counts.get(site.id, 0)
        site_repo.save(site)
