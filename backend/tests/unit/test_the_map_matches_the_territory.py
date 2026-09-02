"""`scripts/README.md` lists what CI runs, and drifted twenty entries behind it.

The map is the only place a reader learns which checks exist. It named
twelve while the workflow ran thirty-two, so two thirds of the verification
this repository does was undiscoverable — including every check added in the
week the drift happened.

Remembering to update it is what failed. This checks it instead.
"""
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
_WORKFLOW = _ROOT / ".github" / "workflows" / "ci.yml"
_MAP = _ROOT / "scripts" / "README.md"

#: `scripts/<name>.py` wherever it appears.
_IN_WORKFLOW = re.compile(r"scripts/([a-z_]+)\.py")
#: A backticked script name in a table cell.
_ON_MAP = re.compile(r"`([a-z_]+)\.py")


def _scripts(pattern: re.Pattern[str], path: Path) -> set[str]:
    return set(pattern.findall(path.read_text()))


class TestEveryCheckCiRunsIsOnTheMap:
    def test_the_map_names_them_all(self) -> None:
        missing = _scripts(_IN_WORKFLOW, _WORKFLOW) - _scripts(_ON_MAP, _MAP)

        assert not missing, (
            "CI runs these and scripts/README.md does not mention them: "
            f"{sorted(missing)}"
        )

    def test_the_map_names_nothing_that_does_not_exist(self) -> None:
        absent = {
            name for name in _scripts(_ON_MAP, _MAP)
            if not (_ROOT / "scripts" / f"{name}.py").exists()
        }

        assert not absent, f"named on the map, not in scripts/: {sorted(absent)}"

    def test_the_workflow_runs_nothing_that_does_not_exist(self) -> None:
        absent = {
            name for name in _scripts(_IN_WORKFLOW, _WORKFLOW)
            if not (_ROOT / "scripts" / f"{name}.py").exists()
        }

        assert not absent, f"CI runs a script that is not there: {sorted(absent)}"
