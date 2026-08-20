"""The version must agree everywhere it is written down.

Before 2.0.0 it did not: the FastAPI app said 2.1.0, the sidebar hardcoded
2.1.0 in a template, ``pyproject.toml`` said 0.1.0, ``package.json`` said
1.0.0 and the newest git tag was v1.0.4 — five answers to one question.
"""
import json
import re
import tomllib
from pathlib import Path

import pytest

from config import APP_VERSION

_BACKEND = Path(__file__).resolve().parents[2]
_REPO = _BACKEND.parent


def test_version_is_semver() -> None:
    assert re.fullmatch(r"\d+\.\d+\.\d+", APP_VERSION), APP_VERSION


def test_pyproject_matches() -> None:
    with (_BACKEND / "pyproject.toml").open("rb") as fh:
        pyproject = tomllib.load(fh)
    assert pyproject["project"]["version"] == APP_VERSION


def test_package_json_matches() -> None:
    package = json.loads((_REPO / "frontend" / "package.json").read_text())
    assert package["version"] == APP_VERSION


def test_changelog_documents_this_version() -> None:
    changelog = (_REPO / "CHANGELOG.md").read_text()
    assert f"## [{APP_VERSION}]" in changelog, (
        f"CHANGELOG.md has no section for {APP_VERSION}"
    )


@pytest.mark.parametrize("path", [
    "frontend/src/components/layout/Sidebar.vue",
])
def test_ui_does_not_hardcode_a_version(path: str) -> None:
    """The footer must read the injected constant, not a literal."""
    source = (_REPO / path).read_text()
    assert "__APP_VERSION__" in source
    assert not re.search(r"mockdr v\d+\.\d+\.\d+", source), (
        f"{path} hardcodes a version string"
    )


def test_openapi_schema_has_no_duplicate_operation_ids() -> None:
    """Every operation is addressable by a unique id.

    Routes serving several methods from one ``api_route`` emitted the same
    operationId for each, so an OpenAPI client generator collapses or rejects
    them. FastAPI warns rather than failing, which is easy to miss.
    """
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        from main import app

        app.openapi_schema = None  # force a rebuild so the warnings fire
        app.openapi()

    duplicates = [
        str(w.message) for w in caught
        if "Duplicate Operation ID" in str(w.message)
    ]
    assert not duplicates, f"{len(duplicates)} duplicate operation ids: {duplicates[:3]}"
