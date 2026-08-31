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


def module_of(path):
    """The dotted module a file under `backend/` is imported as."""
    parts = path.relative_to(ROOT).with_suffix("").parts
    return ".".join(parts)


def mentions(paths):
    """Which identifiers each file names, `def` lines excluded.

    Counted per file rather than in one bag. Counting by name alone said
    every one of 720 functions was reached, because two modules may define
    the same name: `application/cs_cases/commands.py` has a `create_case`
    that no route calls, and it read as reached the whole time because
    `application/es_cases/commands.py` has one that a route does.
    """
    named: dict[pathlib.Path, set] = {}
    for path in paths:
        seen = set()
        for line in path.read_text().splitlines():
            if line.lstrip().startswith(("def ", "async def ")):
                continue
            seen.update(_IDENTIFIER.findall(line))
        named[path] = seen
    return named


#: `from a.b import c` and `import a.b`, capturing the dotted path.
_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import\s+(.+)|import\s+([\w.]+))")


def importers(paths):
    """The dotted modules each file imports.

    Whole paths, not their parts: matching on parts made every file that
    imports *any* `commands` module look like an importer of every other,
    which is how a dead function in `application/cs_cases/commands.py` was
    vouched for by a router importing `application/es_cases/commands.py`.
    """
    imported: dict[pathlib.Path, set] = {}
    for path in paths:
        modules: set = set()
        for line in path.read_text().splitlines():
            match = _IMPORT.match(line)
            if not match:
                continue
            package, names, plain = match.groups()
            if plain:
                modules.add(plain)
            elif package:
                modules.add(package)
                for name in names.replace("(", "").replace(")", "").split(","):
                    bare = name.split(" as ")[0].strip()
                    if bare and bare != "*":
                        modules.add(f"{package}.{bare}")
        imported[path] = modules
    return imported


def main():
    """Report every public function in the read layers that nothing names."""
    paths = sources()
    defs = public_defs(paths)
    named = mentions(paths)
    imports = importers(paths)

    def reached(home, name):
        """Whether anything that can see this definition names it.

        A file counts only if it is the defining module itself or imports
        it. Counting every file made a same-named function in an unrelated
        module vouch for this one, which is how a dead `create_case` in
        `cs_cases` survived every run: `es_cases` has one that a route
        calls. Requiring the mention to come from *outside* was the other
        extreme, and flagged every helper a module calls itself.
        """
        parts = home.relative_to(ROOT).with_suffix("").parts
        # `application.cs_cases.commands`, and the same without the leading
        # `backend` since that is not part of the import path.
        dotted = ".".join(parts)
        own = {dotted, dotted.removeprefix("backend.")}
        for path, seen in named.items():
            if name not in seen:
                continue
            if path == home:
                return True  # a helper its own module calls is reached
            if own & imports.get(path, set()):
                return True
        return False

    flags = [
        (path.relative_to(ROOT), lineno, name)
        for (path, name), lineno in sorted(defs.items())
        if not reached(path, name)
    ]

    print(f"=== UNREACHABLE CODE === {len(defs)} public function(s) read")
    for path, lineno, name in flags:
        print(f"  {str(path) + ':' + str(lineno):52} {name}")
    print(f"\n  {len(flags)} function(s) nothing can reach")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
