"""The limiter must not survive the test that switched it on.

`api.middleware.rate_limit` keeps its config and counters in module globals,
outside the store `generate_all` clears.  A test that enables throttling
therefore hands it to every later test in the same xdist worker, which shows
up as an unrelated test asserting on a body and receiving the 429 envelope.
The root conftest resets it after every test; this proves that reset is
there, without depending on which worker runs what.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2]

_MINI_SUITE = '''
from api.middleware.rate_limit import get_config, set_config

def test_a_switches_throttling_on() -> None:
    set_config(enabled=True, rpm=1)
    assert get_config().enabled is True

def test_b_finds_it_switched_off_again() -> None:
    assert get_config().enabled is False, f"leaked: {get_config()}"
'''


def test_the_root_conftest_puts_the_limiter_back() -> None:
    # The probe has to live under `tests/` for the root conftest to apply to
    # it — that fixture is what is under test — so it cannot go in tmp_path.
    suite = BACKEND / "tests" / "unit" / "test_zz_limiter_leak_probe.py"
    suite.write_text(_MINI_SUITE)
    try:
        done = subprocess.run(  # noqa: S603 - every argument is a literal here
            [sys.executable, "-m", "pytest", str(suite), "-p", "no:cacheprovider",
             "-n0", "-q", "--no-cov", "-o", "addopts="],
            cwd=BACKEND, capture_output=True, text=True, check=False,
        )
    finally:
        suite.unlink(missing_ok=True)
    assert done.returncode == 0, (
        "throttling leaked out of the test that switched it on:\n"
        + done.stdout[-2000:] + done.stderr[-2000:]
    )
