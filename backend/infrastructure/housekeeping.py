"""What a long-running instance forgets, and when.

Every product this mock stands in for forgets the per-request state it hands
out: tokens expire and are deleted, search jobs and scroll contexts are
reaped at their TTL, idle sessions and ack channels time out. The mock
enforced some of those lifetimes when the thing was next *used* and none
when it was not, so an instance up for days under steady traffic kept every
token, job and context any client ever abandoned — bounded only by caps
that, once full, evicted the oldest entry whether or not it was still live.

``sweep`` applies each product's own lifetime to everything at once. The
server runs it every ``SWEEP_INTERVAL_SECONDS`` from its lifespan, and
``/_dev/reset`` runs it before carrying issued credentials over. Each rule
lives with the code that issues the thing, with its vendor source; this
module only calls them.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

from repository.store import store

logger = logging.getLogger(__name__)

#: How often the server sweeps. Every lifetime below is minutes or longer,
#: so a minute's lag only delays freeing memory, never changes an answer:
#: each expiry is also checked when the thing is used.
SWEEP_INTERVAL_SECONDS = 60.0

#: How long an expired Entra or Falcon bearer token is kept after it
#: expired. The tokens are self-contained on the real services, which keep
#: answering "expired" for one; holding it a day keeps that answer for any
#: client still sending it, and bounds the store by a day of issuance
#: rather than by everything ever issued.
EXPIRED_TOKEN_GRACE_SECONDS = 24 * 3600

_ISO_FORMATS = ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ")


def _iso_epoch(text: object) -> float | None:
    for fmt in _ISO_FORMATS:
        try:
            return datetime.strptime(str(text), fmt).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    return None


def _token_expiry(collection: str, record: dict) -> float | None:
    """When a bearer token expires, in epoch seconds; None if it does not say."""
    if collection == "sentinel_oauth_tokens":
        from api.sentinel_auth import TOKEN_TTL_SECONDS

        created = record.get("created_at")
        return float(created) + TOKEN_TTL_SECONDS if created is not None else None
    return _iso_epoch(record.get("expires_at"))


#: The bearer token stores, each keyed by the token itself.
BEARER_TOKEN_COLLECTIONS = (
    "cs_oauth_tokens", "mde_oauth_tokens", "graph_oauth_tokens", "sentinel_oauth_tokens",
)


def reap_bearer_tokens(now: float | None = None, grace: float = EXPIRED_TOKEN_GRACE_SECONDS) -> int:
    """Delete Falcon, Defender, Graph and Sentinel tokens expired longer than *grace*."""
    moment = time.time() if now is None else now
    removed = 0
    for collection in BEARER_TOKEN_COLLECTIONS:
        for key, record in store.get_all_with_keys(collection).items():
            expiry = _token_expiry(collection, record) if isinstance(record, dict) else None
            if expiry is not None and moment > expiry + grace:
                store.delete(collection, key)
                removed += 1
    return removed


def _sweepers() -> dict[str, Callable[[float], int]]:
    from api.routers.es_auth import reap_tokens as reap_es_tokens
    from api.routers.splunk.splunk_hec import reap_idle_channels
    from api.splunk_auth import reap_sessions
    from application.es_search.queries import reap_contexts
    from repository.splunk.search_job_repo import search_job_repo

    return {
        "bearer_tokens": reap_bearer_tokens,
        "es_tokens": reap_es_tokens,
        "splunk_sessions": reap_sessions,
        "splunk_search_jobs": search_job_repo.reap,
        "hec_channels": reap_idle_channels,
        "es_search_contexts": reap_contexts,
    }


def sweep(now: float | None = None) -> dict[str, int]:
    """Apply every lifetime at once; how many things each rule forgot.

    Also settles every pending action whose device has answered
    (``application.settling``), so a pending state does not outlive its
    second for want of a reader.
    """
    from application.settling import settle_due

    moment = time.time() if now is None else now
    freed = {name: reap(moment) for name, reap in _sweepers().items()}
    freed["settled"] = settle_due()
    return freed


async def run_periodically(interval: float | None = None) -> None:
    """Sweep every *interval* seconds until cancelled (the server's lifespan)."""
    while True:
        await asyncio.sleep(interval or SWEEP_INTERVAL_SECONDS)
        try:
            freed = sweep()
        except Exception:  # a failed sweep must not end the loop
            logger.exception("housekeeping sweep failed")
            continue
        if any(freed.values()):
            logger.debug("housekeeping freed %s", freed)


async def reseed_periodically(interval: float) -> None:
    """Re-seed every *interval* seconds until cancelled (``MOCKDR_RESEED_INTERVAL``).

    Exactly ``/_dev/reset``: the data set back to the seed, dated from now,
    with issued credentials kept. See ``config.RESEED_INTERVAL_SECONDS``
    for why a long-running instance needs it.
    """
    from application.dev.commands import reset

    while True:
        await asyncio.sleep(interval)
        try:
            reset()
        except Exception:  # a failed re-seed must not end the loop
            logger.exception("scheduled re-seed failed")
            continue
        logger.info("re-seeded (MOCKDR_RESEED_INTERVAL=%ss)", interval)
