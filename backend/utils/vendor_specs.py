"""Where the vendor references the app reads at run time are found.

In a checkout they are the repository's ``data/vendor-specs``; in an
installed package (``pip install ./backend``) ``setup.py`` copies the ones
the app reads into ``utils/_vendor_specs``.
"""
from __future__ import annotations

from pathlib import Path

_CHECKOUT = Path(__file__).resolve().parents[2] / "data" / "vendor-specs"
_INSTALLED = Path(__file__).resolve().parent / "_vendor_specs"


def spec_path(name: str) -> Path:
    """The path of vendor reference *name*: the checkout's, else the installed copy."""
    checkout = _CHECKOUT / name
    return checkout if checkout.exists() else _INSTALLED / name
