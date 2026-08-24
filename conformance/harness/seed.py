"""Identical events on both targets, so semantics can be compared at all.

The structural probes answer "does mockdr shape its replies like the real
product". They cannot answer "does it *mean* the same thing", because the
real install is empty: a search that matches nothing agrees with everything.

Seeding closes that. The same five events go into both targets' HEC, and the
probes marked ``needs_seed`` then run the same searches against both and
compare the rows themselves. That is how ``tail`` was found to reverse its
output, ``stats ... by`` to sort its groups, and ``_time`` to render as
ISO-8601 rather than as the epoch the pipeline sorts on.

The sourcetype carries a per-run suffix. A real instance keeps what it is
given, and running the probes twice against the same sourcetype would double
every count — which reads as a difference in mockdr rather than as the second
run it is.
"""
from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.clients import Clients
    from harness.spec import PlatformSpec

#: Fixed, so the expectations in the probe file are arithmetic. One event per
#: hour, three hosts, two actions, three users — enough for a group-by to have
#: something to group, and small enough to read in a failure report.
SEED_EVENTS: tuple[dict, ...] = (
    {"offset": 0, "host": "srv-1", "sev": 10, "action": "allow", "user": "alice"},
    {"offset": 1, "host": "srv-1", "sev": 20, "action": "block", "user": "bob"},
    {"offset": 2, "host": "srv-2", "sev": 30, "action": "allow", "user": "alice"},
    {"offset": 3, "host": "srv-2", "sev": 40, "action": "block", "user": "carol"},
    {"offset": 4, "host": "srv-3", "sev": 50, "action": "allow", "user": "alice"},
)

#: The instant the first event is stamped with. Absolute, so a search bounded
#: by `earliest`/`latest` means the same thing on every run — and old enough
#: that no clock skew between the two containers can put it in the future.
SEED_EPOCH = 1787500000

#: Which index the events go to. `main` exists on every Splunk install, and
#: the bootstrap already restricts the real token to it.
SEED_INDEX = "main"


#: The Elasticsearch side of the same idea. Six documents, an explicit date
#: mapping so both engines agree the timestamp is a date, and one document
#: without the sort field so missing-value ordering has something to order.
ES_SEED_INDEX = "conformance-seeded"

ES_SEED_MAPPING: dict = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "host": {"type": "keyword"},
        "sev": {"type": "integer"},
        "name": {"type": "keyword"},
    }},
}

#: Absolute timestamps, so a window written against them means the same thing
#: on every run. Spread over ten days, with two documents sharing a day, so a
#: date_histogram has both a populated gap and an empty one to draw.
ES_SEED_DOCUMENTS: tuple[tuple[str, dict], ...] = (
    ("a", {"@timestamp": "2026-08-01T04:00:00.000Z", "host": "srv-1", "sev": 10, "name": "a"}),
    ("b", {"@timestamp": "2026-08-01T20:00:00.000Z", "host": "srv-1", "sev": 20, "name": "b"}),
    ("c", {"@timestamp": "2026-08-03T09:00:00.000Z", "host": "srv-2", "sev": 30, "name": "c"}),
    ("d", {"@timestamp": "2026-08-10T09:00:00.000Z", "host": "srv-3", "sev": 40, "name": "d"}),
    ("e", {"@timestamp": "2026-08-10T09:00:00.000Z", "host": "srv-2", "sev": 50, "name": "e"}),
    ("f", {"host": "srv-4", "sev": 60, "name": "f"}),
)


class SeedError(RuntimeError):
    """Raised when a target would not take the events."""


def seed_sourcetype() -> str:
    """The sourcetype this run's events carry, unique to the run."""
    return f"probe:conformance:{int(time.time())}"


def _hec_payload(sourcetype: str) -> str:
    """The events as the newline-delimited batch HEC takes."""
    return "\n".join(
        json.dumps({
            "time": SEED_EPOCH + event["offset"] * 3600,
            "host": event["host"],
            "sourcetype": sourcetype,
            "index": SEED_INDEX,
            "event": {k: v for k, v in event.items() if k not in ("offset", "host")},
        })
        for event in SEED_EVENTS
    )


def seed_splunk(
    target: str, clients: Clients, token: str, sourcetype: str,
) -> None:
    """Put the events into one target's HEC.

    Raises:
        SeedError: If the target refused them. A half-seeded comparison is
            worse than none: it reports differences that are only the missing
            half.
    """
    response = clients.get("hec", target).post(
        "/services/collector",
        content=_hec_payload(sourcetype),
        headers={"Authorization": f"Splunk {token}"},
    )
    if response.status_code != 200:
        raise SeedError(
            f"{target} refused the seed events: HTTP {response.status_code} "
            f"{response.text[:200]}",
        )


def await_indexed(
    spec: PlatformSpec, target: str, clients: Clients, sourcetype: str,
) -> None:
    """Block until a search can see the events.

    Indexing is not synchronous on a real Splunk, and a probe that runs
    before the events land compares an empty result against a full one.
    """
    auth = spec.credentials[target].pair if target in spec.credentials else None
    deadline = time.time() + 120
    while time.time() < deadline:
        response = clients.get("management", target).post(
            "/services/search/jobs",
            data={
                "search": f"search index={SEED_INDEX} sourcetype={sourcetype} | stats count",
                "output_mode": "json",
                "exec_mode": "oneshot",
            },
            auth=auth,
        )
        if response.status_code == 200:
            results = response.json().get("results") or [{}]
            if str(results[0].get("count", "0")) == str(len(SEED_EVENTS)):
                return
        time.sleep(2)
    raise SeedError(f"{target} did not index the seed events within 120s")


def seed_elastic(target: str, clients: Clients, auth: object) -> str:
    """Create the seed index on one target and fill it with the documents.

    The index is dropped first: a run has to start from the same six
    documents, and a real cluster keeps what the last run left.

    Returns:
        The index name, for the probes to search.

    Raises:
        SeedError: If the target would not take the index or the documents.
    """
    client = clients.get("search", target)
    client.delete(f"/{ES_SEED_INDEX}", auth=auth)
    created = client.put(f"/{ES_SEED_INDEX}", json=ES_SEED_MAPPING, auth=auth)
    if created.status_code != 200:
        raise SeedError(
            f"{target} would not create {ES_SEED_INDEX}: HTTP "
            f"{created.status_code} {created.text[:200]}",
        )
    for doc_id, source in ES_SEED_DOCUMENTS:
        written = client.put(
            f"/{ES_SEED_INDEX}/_doc/{doc_id}",
            params={"refresh": "true"},
            json=source,
            auth=auth,
        )
        if written.status_code not in (200, 201):
            raise SeedError(
                f"{target} refused seed document {doc_id}: HTTP "
                f"{written.status_code} {written.text[:200]}",
            )
    return ES_SEED_INDEX
