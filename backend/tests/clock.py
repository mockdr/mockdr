"""Move the server's clock forward without sleeping.

Every test runs against a seed seconds old, so nothing that happens to an
instance after an hour — a token expiring, a job reaped, a pending action
left unread for a day — is reached by waiting. The server reads the clock
in two ways, ``time.time()`` / ``time.monotonic()`` and
``datetime.now()``, from modules that imported either; this patches both,
everywhere, for one test.

``datetime.now`` cannot be patched on the C type, so every module whose
``datetime`` name is the real class gets a subclass whose ``now`` is
shifted. Instances stay real ``datetime`` objects; ``isinstance``,
arithmetic and comparisons are unchanged. No dependency: freezegun and
time-machine are not in requirements-dev, and the mock needs nothing they
offer beyond this.
"""
from __future__ import annotations

import datetime as _dt
import sys
import time as _time
from typing import Any

import pytest

_REAL_TIME = _time.time
_REAL_MONOTONIC = _time.monotonic
_REAL_DATETIME = _dt.datetime


class Clock:
    """A shifted clock; ``advance`` moves every reader of it at once."""

    def __init__(self) -> None:
        """Start level with the real clock."""
        self.offset = 0.0

    def advance(self, seconds: float = 0.0, *, days: float = 0.0) -> None:
        """Move the clock forward by *seconds* plus *days*."""
        self.offset += seconds + days * 86400

    def time(self) -> float:
        """``time.time()``, shifted."""
        return _REAL_TIME() + self.offset


def install(monkeypatch: pytest.MonkeyPatch) -> Clock:
    """Patch every clock reader in the process to follow a new ``Clock``."""
    clock = Clock()

    class _ShiftedDatetime(_REAL_DATETIME):
        @classmethod
        def now(cls, tz: Any = None) -> Any:  # noqa: ANN401 - mirrors datetime.now
            return _REAL_DATETIME.now(tz) + _dt.timedelta(seconds=clock.offset)

        @classmethod
        def utcnow(cls) -> Any:  # noqa: ANN401 - mirrors datetime.utcnow
            return _REAL_DATETIME.utcnow() + _dt.timedelta(seconds=clock.offset)

    monkeypatch.setattr(_time, "time", lambda: _REAL_TIME() + clock.offset)
    monkeypatch.setattr(_time, "monotonic", lambda: _REAL_MONOTONIC() + clock.offset)
    for name, module in list(sys.modules.items()):
        if module is None or name.startswith(("_pytest", "pytest", "pluggy")):
            continue
        try:
            if module.__dict__.get("datetime") is _REAL_DATETIME:
                monkeypatch.setattr(module, "datetime", _ShiftedDatetime)
        except (AttributeError, TypeError):
            continue
    return clock
