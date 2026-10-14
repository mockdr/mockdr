"""Build hook: carry the vendor references the app reads at run time into the wheel.

Everything else is declared in pyproject.toml. The three files below live in
the repository's ``data/vendor-specs`` (outside this project directory), and
``utils/vendor_specs.py`` reads them from there in a checkout; an installed
copy reads the ones copied into ``utils/_vendor_specs`` here. Without them an
installed mock still runs, but sorts Graph and Defender enums alphabetically
and answers ``$select`` without the vendors' property lists.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

_SOURCE = Path(__file__).resolve().parent.parent / "data" / "vendor-specs"
_RUNTIME_SPECS = ("graph_v1.0_csdl_types.json", "graph_v1.0_reduced.json", "mde_docs_reduced.json")


class _BuildWithVendorSpecs(build_py):  # type: ignore[misc]
    def run(self) -> None:
        super().run()
        target = Path(self.build_lib) / "utils" / "_vendor_specs"
        target.mkdir(parents=True, exist_ok=True)
        for name in _RUNTIME_SPECS:
            if (_SOURCE / name).exists():
                shutil.copy2(_SOURCE / name, target / name)


setup(cmdclass={"build_py": _BuildWithVendorSpecs})
