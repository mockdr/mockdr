"""Installed-apps seeder — seeds application inventory for agents.

EDR agents are installed on ~90% of endpoints with version variation
(including outdated and EOL versions) to support NIS2, ISO 27001,
and SOC compliance testing.  Non-EDR apps are sampled randomly.
"""
import random

from faker import Faker

from infrastructure.seeders._shared import APP_CATALOG, EDR_VERSION_POOL, rand_ago
from repository.store import store
from utils.id_gen import new_id

# EDR product names from the catalog (match keys in EDR_VERSION_POOL)
_EDR_NAMES: set[str] = set(EDR_VERSION_POOL.keys())


def seed_installed_apps(fake: Faker, agent_ids: list[str]) -> None:
    """Seed installed application records for all agents.

    EDR agents are installed on ~90% of endpoints with weighted version
    selection (70% current, 30% outdated/EOL).  Standard software is
    sampled randomly on a subset of agents.

    Args:
        fake: Shared :class:`~faker.Faker` instance (seeded externally).
        agent_ids: Full list of agent IDs.
    """
    non_edr_apps = [
        (name, ver, vendor)
        for name, ver, vendor in APP_CATALOG
        if name not in _EDR_NAMES
    ]

    for aid in agent_ids:
        # ── EDR agents: ~90% coverage per product, version variation ─────
        for edr_name, versions in EDR_VERSION_POOL.items():
            if random.random() > 0.90:
                continue  # ~10% of endpoints missing this EDR

            # Weighted selection: 70% chance of current, 30% outdated/EOL
            current = [v for v, is_current in versions if is_current]
            outdated = [v for v, is_current in versions if not is_current]
            if outdated and random.random() < 0.30:
                version = random.choice(outdated)
            else:
                version = random.choice(current)

            vendor = next(
                v for n, _, v in APP_CATALOG if n == edr_name
            )
            app_id = new_id()
            store.save("installed_apps", app_id, {
                "id": app_id,
                "agentId": aid,
                "name": edr_name,
                "version": version,
                "publisher": vendor,
                "publisherName": vendor,
                "installedDate": rand_ago(200),
                "size": random.randint(52428800, 209715200),  # 50-200 MB
                "type": "application",
                "riskLevel": "none",
            })

        # ── Standard software: random sample on each agent ───────────────
        sample_count = random.randint(4, 10)
        for app_name, app_ver, vendor in random.sample(
            non_edr_apps, min(sample_count, len(non_edr_apps)),
        ):
            app_id = new_id()
            store.save("installed_apps", app_id, {
                "id": app_id,
                "agentId": aid,
                "name": app_name,
                "version": app_ver,
                "publisher": vendor,
                "publisherName": vendor,
                "installedDate": rand_ago(200),
                "size": random.randint(10240, 2097152),
                "type": "application",
                "riskLevel": random.choice(
                    ["none"] * 4 + ["low", "medium", "high"],
                ),
            })
