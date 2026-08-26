# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Find an application function nothing can reach.

The sibling `unread_params.py` reads the source for a parameter a handler
never looks at. This one reads it for the layer below: a query or command
handler no router calls, no other module imports, and no test names.

Dead code in a mock is not merely untidy. What was found the first time this
ran was `cs_iocs.device_count_for_ioc`, which answered how many devices had
seen an indicator with `(hash(value) % 10) + 1` — a number Python randomises
per process, unrelated to any device this install has. It served nobody
because no route was ever wired to it; had one been wired, the mock would
have answered a confident count that was invented twice differently across a
restart. The same file's `processes_ran_on` invented process ids the same
way. Everything else the sweep found was a handler superseded by the
collection route the vendor actually documents — `get_agent_passphrase` for
one agent where SentinelOne publishes `/agents/passphrases` for all of them.

Only `application/`, `utils/`, `repository/` and `domain/` are read. Routers
are not: a route handler is reached through its decorator and is never named
by anything, so every one of them would be flagged.

A name is counted as reached if it appears anywhere in the tree outside its
own `def` line — in a call, an import, an `__all__`, a getattr string, or a
test. That is deliberately generous: this sweep should never be the reason a
reachable function is deleted.

    backend/.venv/bin/python scripts/unreachable_code.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import ast
import collections
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "backend"

#: The layers this sweep reads. `api/` is left out on purpose — see above.
_LAYERS = ("application", "utils", "repository", "domain")

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*")


def sources():
    """Every Python file in the backend, virtualenvs excluded."""
    return [p for p in sorted(ROOT.rglob("*.py")) if ".venv" not in p.parts]


def public_defs(paths):
    """Module-level public functions in the layers this sweep reads."""
    found = {}
    for path in paths:
        parts = path.relative_to(ROOT).parts
        if parts[0] not in _LAYERS or "tests" in parts:
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    found[(path, node.name)] = node.lineno
    return found


def mentions(paths):
    """How often each identifier occurs, `def` lines excluded."""
    counted: collections.Counter = collections.Counter()
    for path in paths:
        for line in path.read_text().splitlines():
            if line.lstrip().startswith(("def ", "async def ")):
                continue
            counted.update(_IDENTIFIER.findall(line))
    return counted


def main():
    """Report every public function in the read layers that nothing names."""
    paths = sources()
    defs = public_defs(paths)
    reached = mentions(paths)

    flags = [
        (path.relative_to(ROOT), lineno, name)
        for (path, name), lineno in sorted(defs.items())
        if not reached[name]
    ]

    print(f"=== UNREACHABLE CODE === {len(defs)} public function(s) read")
    for path, lineno, name in flags:
        print(f"  {str(path) + ':' + str(lineno):52} {name}")
    print(f"\n  {len(flags)} function(s) nothing can reach")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
