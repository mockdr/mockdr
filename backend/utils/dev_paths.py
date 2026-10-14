"""Which request paths are mockdr's own control surface.

The middlewares that leave ``/_dev`` alone (rate limiting, fault injection,
tenant scoping, the recording proxy, metrics, the audit log) used to ask
whether ``"/_dev/"`` occurred *anywhere* in the path. A vendor path can carry
that segment as an index, an id or a namespace — ``/elastic/_cat/indices/_dev/``
answers 200 — and such a request slipped past the rate limiter and fault
injection. The control routes live under one prefix, so that is the test.
"""
from __future__ import annotations

from config import API_PREFIX

DEV_PREFIX = f"{API_PREFIX}/_dev/"


def is_dev_path(path: str) -> bool:
    """Whether *path* is one of mockdr's ``/_dev`` control routes."""
    return path.startswith(DEV_PREFIX)
