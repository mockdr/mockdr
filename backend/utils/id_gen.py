"""SentinelOne-style identifier generation.

``generate_all`` documents that "the RNG is re-seeded at entry so repeated
calls always produce the same data set", and it does seed ``random`` and
``Faker`` — but ids came from ``secrets.randbelow``, a CSPRNG that cannot be
seeded, and UUIDs from ``uuid4()``. So every id and uuid in the store changed
on every restart and on every ``POST /_dev/reset``, breaking anything that
pinned one: a saved connector config, a fixture, a recorded playbook.

Ids here are object identifiers in a mock, not credentials, so a seeded PRNG
is the right source. Real secrets — API tokens, session keys — still come from
:mod:`secrets` where they are minted.
"""
from __future__ import annotations

import random
import threading
import uuid

__all__ = ["new_hex", "new_id", "new_uuid", "reseed"]

_DEFAULT_SEED = 42

_lock = threading.Lock()
_rng = random.Random(_DEFAULT_SEED)  # noqa: S311 - identifiers, not secrets


def reseed(seed: int = _DEFAULT_SEED) -> None:
    """Restart the identifier sequence, so a re-seed reproduces the same ids."""
    with _lock:
        _rng.seed(seed)


def new_id() -> str:
    """Generate a SentinelOne-style 19-digit numeric ID (thread-safe)."""
    with _lock:
        return str(10**17 + _rng.randrange(9 * 10**17))


def new_uuid() -> str:
    """Generate a UUID drawn from the same reproducible sequence.

    ``uuid.uuid4()`` reads the OS entropy pool and cannot be seeded, so
    seeders that call it produce a different store on every run.
    """
    with _lock:
        return str(uuid.UUID(int=_rng.getrandbits(128), version=4))


def new_hex() -> str:
    """A UUID with the dashes removed, for ids that use the compact form."""
    return new_uuid().replace("-", "")
