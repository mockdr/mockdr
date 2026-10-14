"""The random source a dev scenario draws its targets from.

Scenarios picked their agents, devices and users with the module-level
``random`` — the stream ``generate_all`` seeds for the seed data and leaves
for whoever draws next. Fault injection, an XDR route and every earlier
scenario drew from it too, so which twenty agents ``mass_infection`` hit
after a reset depended on the requests served since: a test asserting on
the scenario's effect passed alone and failed after another test.

Each run now draws from its own generator, seeded by the scenario's name and
how many times it has run since the last seed. The first ``mass_infection``
after a reset hits the same agents every time; a second run in the same
session hits a different, equally reproducible set.
"""
from __future__ import annotations

import random
import threading

_lock = threading.Lock()
_runs: dict[str, int] = {}


def scenario_rng(scenario: str) -> random.Random:
    """The generator for the next run of *scenario*."""
    with _lock:
        run = _runs.get(scenario, 0)
        _runs[scenario] = run + 1
    return random.Random(f"scenario:{scenario}:{run}")  # noqa: S311 - simulation, not security


def reset_scenario_runs() -> None:
    """Start every scenario's sequence over; called by each re-seed."""
    with _lock:
        _runs.clear()
