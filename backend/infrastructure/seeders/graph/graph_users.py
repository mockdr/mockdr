"""Graph Users seeder -- creates Entra ID user records.

Extracts unique usernames from MDE machine ``loggedOnUsers`` and pads
with Faker-generated employees to reach 25 total users.
"""
from __future__ import annotations

import random

from faker import Faker

from domain.graph.user import GraphUser
from infrastructure.seeders._shared import rand_ago
from infrastructure.seeders.graph.graph_shared import (
    GRAPH_DOMAIN,
    SKU_ID_M365_BUSINESS_PREMIUM,
    SKU_ID_M365_E3,
    SKU_ID_M365_E5,
    graph_uuid,
)
from repository.graph.user_repo import graph_user_repo
from repository.mde_machine_repo import mde_machine_repo
from repository.store import store

_TARGET_COUNT: int = 25

_DEPARTMENTS: list[str] = [
    "IT", "Finance", "Marketing", "Sales", "HR",
    "Engineering", "Legal", "Operations", "Executive",
]

_JOB_TITLES: dict[str, list[str]] = {
    "IT": ["IT Administrator", "Systems Engineer", "Help Desk Analyst", "Network Engineer"],
    "Finance": ["Financial Analyst", "Accountant", "Controller", "Finance Manager"],
    "Marketing": ["Marketing Manager", "Content Strategist", "Brand Analyst", "SEO Specialist"],
    "Sales": ["Account Executive", "Sales Manager", "Business Development Rep", "Sales Engineer"],
    "HR": ["HR Generalist", "Recruiter", "HR Manager", "Benefits Coordinator"],
    "Engineering": ["Software Engineer", "DevOps Engineer", "QA Engineer", "Engineering Manager"],
    "Legal": ["Corporate Counsel", "Paralegal", "Compliance Analyst", "Legal Operations Manager"],
    "Operations": ["Operations Manager", "Project Manager", "Business Analyst", "Process Improvement Lead"],
    "Executive": ["Chief Executive Officer", "Chief Technology Officer", "Chief Financial Officer", "Vice President"],
}

_CITIES: list[str] = [
    "New York", "San Francisco", "Chicago", "Seattle", "Austin",
    "Boston", "Denver", "Atlanta", "Los Angeles", "Dallas",
]

_COUNTRIES: list[str] = ["United States"]

_OFFICE_LOCATIONS: list[str] = [
    "HQ - Floor 3", "HQ - Floor 5", "HQ - Floor 7",
    "Branch - West", "Branch - East", "Remote",
]

_LICENSE_POOLS: list[list[dict]] = [
    [{"disabledPlans": [], "skuId": SKU_ID_M365_E5}],
    [{"disabledPlans": [], "skuId": SKU_ID_M365_E3}],
    [{"disabledPlans": [], "skuId": SKU_ID_M365_BUSINESS_PREMIUM}],
    [
        {"disabledPlans": [], "skuId": SKU_ID_M365_E5},
        {"disabledPlans": [], "skuId": SKU_ID_M365_E3},
    ],
]


def _build_sign_in_activity(enabled: bool) -> dict:
    """Generate signInActivity based on account status.

    Disabled accounts get sign-in timestamps at least 60 days ago
    (former employees) to simulate realistic offboarding gaps.
    Non-interactive sign-ins may be more recent (app tokens not revoked).
    """
    if enabled:
        last_sign_in = rand_ago(max_days=30)
        last_non_interactive = rand_ago(max_days=7)
    else:
        # Former employee: last interactive sign-in 60-180 days ago
        from datetime import UTC, datetime, timedelta
        days_ago = random.randint(60, 180)
        ts = datetime.now(UTC) - timedelta(days=days_ago, hours=random.randint(0, 23))
        last_sign_in = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        # Non-interactive (app tokens) may still be active — 15-90 days ago
        # This is a compliance violation: tokens not revoked after offboarding
        ni_days = random.randint(15, 90)
        ni_ts = datetime.now(UTC) - timedelta(days=ni_days, hours=random.randint(0, 23))
        last_non_interactive = ni_ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return {
        "lastSignInDateTime": last_sign_in,
        "lastNonInteractiveSignInDateTime": last_non_interactive,
    }


def seed_graph_users(fake: Faker) -> list[str]:
    """Create 25 Entra ID user records.

    Extracts unique usernames from MDE machine ``loggedOnUsers`` first,
    then pads with Faker-generated employees to reach the target count.

    Args:
        fake: Shared Faker instance (seeded externally).

    Returns:
        List of Graph user ID strings.
    """
    user_ids: list[str] = []

    # ── Step 1: Extract unique usernames from MDE loggedOnUsers ──────────
    mde_usernames: list[str] = []
    seen: set[str] = set()
    for machine in mde_machine_repo.list_all():
        for logged_on in machine.loggedOnUsers:
            account_name = logged_on.get("accountName", "")
            if account_name and account_name not in seen:
                seen.add(account_name)
                mde_usernames.append(account_name)

    # ── Step 2: Build user list — MDE usernames first, then Faker ───────
    user_specs: list[tuple[str, str]] = []  # (first_name, last_name)

    for username in mde_usernames:
        # Treat the username as a first.last style or single name
        parts = username.split(".")
        if len(parts) >= 2:
            first = parts[0].capitalize()
            last = parts[1].capitalize()
        else:
            first = username.capitalize()
            last = fake.last_name()
        user_specs.append((first, last))

    # Pad with Faker employees to reach target count
    while len(user_specs) < _TARGET_COUNT:
        first = fake.first_name()
        last = fake.last_name()
        user_specs.append((first, last))

    # Trim to target if MDE had more than 25 unique users
    user_specs = user_specs[:_TARGET_COUNT]

    # ── Step 3: Create GraphUser records ────────────────────────────────
    from datetime import UTC, datetime, timedelta

    for _i, (first, last) in enumerate(user_specs):
        user_id = graph_uuid()
        user_ids.append(user_id)

        upn = f"{first.lower()}.{last.lower()}@{GRAPH_DOMAIN}"
        mail = f"{first.lower()}.{last.lower()}@{GRAPH_DOMAIN}"
        department = random.choice(_DEPARTMENTS)
        job_title = random.choice(_JOB_TITLES[department])

        # Distribution: ~72% enabled active, ~8% enabled stale, ~20% disabled
        roll = random.random()
        if roll < 0.72:
            enabled = True
            stale = False
        elif roll < 0.80:
            # Stale account: enabled but no sign-in for 90-200 days
            # Compliance violation: account should be reviewed or disabled
            enabled = True
            stale = True
        else:
            enabled = False
            stale = False

        if stale:
            days_ago = random.randint(90, 200)
            ts = datetime.now(UTC) - timedelta(days=days_ago, hours=random.randint(0, 23))
            sign_in_activity = {
                "lastSignInDateTime": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "lastNonInteractiveSignInDateTime": rand_ago(max_days=60),
            }
        else:
            sign_in_activity = _build_sign_in_activity(enabled)

        assigned_licenses = random.choice(_LICENSE_POOLS)
        created = rand_ago(max_days=365 * 2)

        user = GraphUser(
            id=user_id,
            userPrincipalName=upn,
            displayName=f"{first} {last}",
            mail=mail,
            givenName=first,
            surname=last,
            jobTitle=job_title,
            department=department,
            officeLocation=random.choice(_OFFICE_LOCATIONS),
            mobilePhone=fake.phone_number() if random.random() < 0.7 else None,
            businessPhones=[fake.phone_number()] if random.random() < 0.6 else [],
            accountEnabled=enabled,
            companyName="AcmeCorp",
            city=random.choice(_CITIES),
            country=random.choice(_COUNTRIES),
            assignedLicenses=assigned_licenses,
            assignedPlans=[],
            createdDateTime=created,
            signInActivity=sign_in_activity,
        )
        graph_user_repo.save(user)

        # Store cross-vendor reference in edr_id_map
        mapping = store.get("edr_id_map", user_id) or {}
        mapping["graph_user_id"] = user_id
        store.save("edr_id_map", user_id, mapping)

    # ── Step 4: Add guest/external users (compliance violation: unmanaged B2B) ──
    guest_domains = ["partner-corp.com", "contractor-agency.net", "freelancer.io"]
    for gi in range(3):
        guest_id = graph_uuid()
        user_ids.append(guest_id)
        g_first = fake.first_name()
        g_last = fake.last_name()
        ext_domain = guest_domains[gi % len(guest_domains)]
        guest = GraphUser(
            id=guest_id,
            userPrincipalName=f"{g_first.lower()}.{g_last.lower()}_{ext_domain}#EXT#@{GRAPH_DOMAIN}",
            displayName=f"{g_first} {g_last} (External)",
            mail=f"{g_first.lower()}.{g_last.lower()}@{ext_domain}",
            givenName=g_first,
            surname=g_last,
            jobTitle="External Contractor" if gi < 2 else "Partner Consultant",
            department=None,
            officeLocation=None,
            accountEnabled=True,
            companyName=ext_domain.split(".")[0].replace("-", " ").title(),
            assignedLicenses=[],
            assignedPlans=[],
            createdDateTime=rand_ago(max_days=180),
            signInActivity={
                "lastSignInDateTime": rand_ago(max_days=14),
                "lastNonInteractiveSignInDateTime": rand_ago(max_days=3),
            },
        )
        graph_user_repo.save(guest)

    return user_ids
