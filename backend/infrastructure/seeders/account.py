"""Account seeder — seeds the single top-level account record."""
from faker import Faker

from config import SEED_COUNT_AGENTS
from domain.account import Account
from infrastructure.seeders._shared import ago
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
        numberOfSites=3,
        numberOfAgents=SEED_COUNT_AGENTS,
        activeAgents=SEED_COUNT_AGENTS,
        numberOfUsers=5,
        accountType="Trial",
        isDefault=True,
    ))
    return account_id, _ACCOUNT_NAME
