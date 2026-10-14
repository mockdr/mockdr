"""The seed is the same store in every process, not only within one.

``generate_all`` re-seeds ``random``, Faker and the id generator, and the
in-process idempotency test (`TestSeedIsReproducible`) passed — yet three
things still changed on every restart, because they only vary *between*
processes:

* the builtin ``hash()`` of a str is salted per process (``PYTHONHASHSEED``),
  and Defender's ``rbacGroupId`` was ``hash(groupId) % 10000`` — copied on
  into Graph alert evidence and the Splunk events;
* a Graph incident was named after ``next(iter(<set of categories>))``, and a
  set of strings iterates in hash order;
* the sign-in log's application ids were ``graph_uuid()`` calls run at
  import, before ``generate_all`` seeds the stream.

Each test here seeds in two fresh interpreters with different hash salts and
compares what they built, with wall-clock timestamps masked (the seed dates
records relative to *now*, so those legitimately move).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

_BACKEND = Path(__file__).resolve().parents[3]

#: Seeds, then prints every collection as JSON with the clock masked: ISO
#: dates and datetimes, and epoch seconds/milliseconds whether stored as a
#: number or embedded in a string (Splunk's `_raw`, XDR's epoch-ms fields).
_DUMP = r"""
import dataclasses, json, re, sys
from infrastructure.seed import generate_all
from repository.store import store
from utils.serde import record_dict

ISO = re.compile(r"\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?")
EPOCH = re.compile(r"(?<!\d)(1[5-9]\d{8}|1[5-9]\d{11})(\.\d+)?(?!\d)")
SLASH = re.compile(r"\d{2}/\d{2}/\d{4}[ :]\d{2}:\d{2}:\d{2}(\.\d+)?")

def mask(v):
    if isinstance(v, str):
        return SLASH.sub("<T>", EPOCH.sub("<T>", ISO.sub("<T>", v)))
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return "<T>" if (1.5e9 <= v <= 2.1e9 or 1.5e12 <= v <= 2.1e12) else v
    if isinstance(v, dict):
        return {str(mask(k)): mask(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [mask(x) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    return mask(str(v))

generate_all()
out = {}
for name, records in store._collections.items():
    out[name] = mask({
        k: record_dict(r) if dataclasses.is_dataclass(r) else r
        for k, r in records.items()
    })
json.dump(out, sys.stdout, sort_keys=True, default=str)
"""


def _seed_in_fresh_process(hash_seed: str) -> dict[str, Any]:
    env = {**os.environ, "PYTHONHASHSEED": hash_seed}
    result = subprocess.run(  # noqa: S603 - our own interpreter, our own script
        [sys.executable, "-c", _DUMP],
        cwd=_BACKEND, env=env, capture_output=True, text=True, check=True,
        timeout=300,
    )
    return json.loads(result.stdout)


@pytest.fixture(scope="module")
def two_processes() -> tuple[dict[str, Any], dict[str, Any]]:
    """The store as two interpreters with different hash salts seed it."""
    return _seed_in_fresh_process("1"), _seed_in_fresh_process("2")


class TestHashSaltDoesNotReachTheSeed:
    """Values that depended on the per-process hash salt."""

    def test_rbac_group_id_is_the_same_in_every_process(
        self, two_processes: tuple[dict[str, Any], dict[str, Any]],
    ) -> None:
        """``hash(groupId) % 10000`` gave each restart new RBAC groups."""
        first, second = two_processes

        def rbac(store: dict[str, Any]) -> dict[str, Any]:
            return {k: m["rbacGroupId"] for k, m in store["mde_machines"].items()}

        assert rbac(first) == rbac(second)

    def test_incident_names_are_the_same_in_every_process(
        self, two_processes: tuple[dict[str, Any], dict[str, Any]],
    ) -> None:
        """A set's iteration order named a third of the incidents per process."""
        first, second = two_processes

        def names(store: dict[str, Any]) -> dict[str, str]:
            return {
                k: i["displayName"]
                for k, i in store["graph_security_incidents"].items()
            }

        assert names(first) == names(second)


class TestSignInApplicationsAreMicrosofts:
    """The sign-in log names Microsoft's first-party apps by their real ids."""

    WELL_KNOWN = {
        "Microsoft Teams": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
        "Office 365 Exchange Online": "00000002-0000-0ff1-ce00-000000000000",
        "Microsoft 365 Portal": "00000006-0000-0ff1-ce00-000000000000",
        "Microsoft Graph Explorer": "de8bc8b5-d9f9-48b1-a8ad-b748da725064",
    }

    def test_app_ids_are_the_first_party_ids(
        self, two_processes: tuple[dict[str, Any], dict[str, Any]],
    ) -> None:
        """Import-time ``graph_uuid()`` gave every process start new app ids."""
        for store in two_processes:
            for entry in store["graph_sign_in_logs"].values():
                assert entry["appId"] == self.WELL_KNOWN[entry["appDisplayName"]]
                assert entry["resourceId"] == entry["appId"]


class TestEveryCollectionIsTheSameInEveryProcess:
    """The whole store, clock masked, is one store whatever the hash salt."""

    def test_no_collection_differs(
        self, two_processes: tuple[dict[str, Any], dict[str, Any]],
    ) -> None:
        first, second = two_processes
        assert set(first) == set(second)
        differing = sorted(name for name in first if first[name] != second[name])
        assert not differing, (
            f"collections that differ between two processes seeding the same "
            f"seed: {differing}"
        )
