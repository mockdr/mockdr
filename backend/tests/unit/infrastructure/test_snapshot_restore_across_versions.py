"""A snapshot restored after an upgrade, and an import under traffic.

* A snapshot from 2.5 loaded with 2.5's vocabulary intact — Cortex
  endpoints ``isolated``, SentinelOne threats ``killed``, XQL ``completed``
  — values 2.6 never writes, never settles out of, and no client comparison
  matches. They are rewritten to this release's on import.
* An import cleared the store and refilled it with no lock held, so a
  request served meanwhile found no API tokens (a 401) or half the data.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from application.dev.commands import export_state, import_state, reset
from infrastructure import seed
from infrastructure.persistence import PersistenceManager
from repository.store import store


def test_a_two_five_snapshot_comes_back_in_this_releases_words(tmp_path: Path) -> None:
    seed.generate_all()
    snapshot = export_state()
    snapshot["_version"] = "2.5.0"
    snapshot["xdr_endpoints"][0]["is_isolated"] = "isolated"
    snapshot["xdr_endpoints"][1]["is_isolated"] = "unisolated"
    snapshot["threats"][0]["threatInfo"]["mitigationStatus"] = "killed"
    snapshot["threats"][1]["threatInfo"]["mitigationStatus"] = "active"
    snapshot["xdr_xql_queries"] = [{"query_id": "q1", "status": "completed", "query": "x"}]
    endpoint_ids = [e["endpoint_id"] for e in snapshot["xdr_endpoints"][:2]]
    threat_ids = [t["id"] for t in snapshot["threats"][:2]]
    path = tmp_path / "state.json"
    path.write_text(json.dumps(snapshot, default=str))

    assert PersistenceManager(path).load_if_exists() is True

    endpoints = [store.get("xdr_endpoints", i) for i in endpoint_ids]
    assert [e.is_isolated for e in endpoints] == ["AGENT_ISOLATED", "AGENT_UNISOLATED"]
    threats = [store.get("threats", i).threatInfo for i in threat_ids]
    assert [t["mitigationStatus"] for t in threats] == ["mitigated", "not_mitigated"]
    assert threats[0]["mitigationStatusDescription"] == "Mitigated"
    assert store.get("xdr_xql_queries", "q1").status == "SUCCESS"


def test_a_current_snapshot_is_not_rewritten() -> None:
    seed.generate_all()
    assert import_state(export_state())["data"]["migrated"] == 0


def test_a_reader_never_sees_the_store_half_imported() -> None:
    seed.generate_all()
    snapshot = export_state()
    # The API tokens are restored last, after every typed collection: the
    # widest window in which a request found itself unauthenticated.
    expected = (store.count("agents"), store.count("api_tokens"))
    seen: list[tuple[int, int]] = []
    done = threading.Event()

    def read() -> None:
        while not done.is_set():
            with store._lock:
                seen.append((store.count("agents"), store.count("api_tokens")))

    reader = threading.Thread(target=read)
    reader.start()
    try:
        for _ in range(5):
            import_state(json.loads(json.dumps(snapshot, default=str)))
    finally:
        done.set()
        reader.join()
    reset()

    assert seen and set(seen) == {expected}, sorted(set(seen))
