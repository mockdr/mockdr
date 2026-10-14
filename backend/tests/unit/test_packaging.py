"""`pip install ./backend` builds, and the install carries what mockdr.testing starts.

ADR-013 ships `mockdr.testing` for external suites, which start the whole app
(`"main:app"`). pyproject.toml named `setuptools.backends.legacy:build` as its
build backend, a module setuptools does not have, so the install failed
before it built anything. These check the build configuration offline; the
full install is exercised by hand into a throwaway venv (TESTING.md,
"Using mockdr from another test suite").
"""
from __future__ import annotations

import fnmatch
import importlib.util
import tomllib
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[2]
CONFIG = tomllib.loads((BACKEND / "pyproject.toml").read_text())


#: The PEP 517 backends setuptools provides (setuptools/build_meta.py).
_SETUPTOOLS_BACKENDS = {"setuptools.build_meta", "setuptools.build_meta:__legacy__"}


def test_the_build_backend_is_one_setuptools_provides() -> None:
    backend = CONFIG["build-system"]["build-backend"]
    assert backend in _SETUPTOOLS_BACKENDS, backend


def test_the_build_backend_imports_where_setuptools_is_installed() -> None:
    if importlib.util.find_spec("setuptools") is None:
        pytest.skip("setuptools is not installed here; pip installs it to build")
    module, _, attribute = CONFIG["build-system"]["build-backend"].partition(":")
    backend = importlib.import_module(module)
    target = getattr(backend, attribute) if attribute else backend
    for hook in ("build_wheel", "build_sdist", "get_requires_for_build_wheel"):
        assert hasattr(target, hook), hook


def test_metadata_reads_nothing_outside_the_project() -> None:
    """setuptools refuses a readme or licence file outside backend/."""
    readme = CONFIG["project"].get("readme")
    assert not (isinstance(readme, str) and readme.startswith("..")), readme
    classifiers = CONFIG["project"].get("classifiers", [])
    # PEP 639: a licence expression and a licence classifier are an error.
    assert not [c for c in classifiers if c.startswith("License ::")]


def _packaged() -> set[str]:
    """What ``[tool.setuptools.packages.find]`` selects: every directory under
    backend/ (namespace packages included) whose dotted name matches an
    ``include`` glob -- setuptools' own rule for the find directive."""
    include = CONFIG["tool"]["setuptools"]["packages"]["find"]["include"]
    names = {
        ".".join(d.relative_to(BACKEND).parts) for d in BACKEND.rglob("*")
        if d.is_dir() and "__pycache__" not in d.parts
    }
    return {n for n in names if any(fnmatch.fnmatchcase(n, g) for g in include)}


#: What lives under backend/ and is not the app: the tests, a local venv, and
#: what a local `pip install ./backend` leaves behind.
_NOT_SHIPPED = ("tests", ".venv", "build")


def test_every_package_the_app_imports_is_installed() -> None:
    packaged = _packaged()
    tops = {
        p.name for p in BACKEND.iterdir()
        if p.is_dir() and any(p.glob("*.py")) and p.name not in _NOT_SHIPPED
    }
    assert tops <= {name.split(".")[0] for name in packaged}, tops
    for init in BACKEND.rglob("__init__.py"):
        rel = init.parent.relative_to(BACKEND)
        if rel.parts and rel.parts[0] not in _NOT_SHIPPED:
            assert ".".join(rel.parts) in packaged, rel
    assert set(CONFIG["tool"]["setuptools"]["py-modules"]) >= {"main", "config"}


def test_every_fixture_the_routes_answer_from_is_package_data() -> None:
    globs = CONFIG["tool"]["setuptools"]["package-data"]["infrastructure"]
    root = BACKEND / "infrastructure"
    missing = [
        str(path.relative_to(root)) for path in (root / "fixtures").rglob("*")
        if path.is_file() and not any(fnmatch.fnmatch(str(path.relative_to(root)), g)
                                      for g in globs)
    ]
    assert not missing, missing
