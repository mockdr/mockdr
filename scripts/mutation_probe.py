# ruff: noqa: ANN001, ANN002, ANN201, ANN202, D103, E402, S101, S603, T201
"""Inject one defect at a time and ask whether anything notices.

Every other check here reports what it found. This one measures the checks
themselves, because "no failures" says nothing about the failures a suite
would miss -- and the answer, the first time it was asked, was that half of
them would.

Ten defects were injected into a spread of old code and code written the
same week: a comparison flipped, a sort reversed, a boundary loosened. Five
went through 4975 tests and 32 audits without a murmur. Among them the
default order of `/threats` (newest-first became oldest-first), a machine's
vulnerabilities becoming a neighbour's, and the last page of a Graph
collection announcing another that is not there.

The point is not the number but the direction: run it, and whatever survives
is a behaviour nothing is checking. Restoring the tree is guarded by
`atexit` and by the three signals a timeout arrives as, because a harness
that leaves a mutation behind is worse than no harness.

    backend/.venv/bin/python scripts/mutation_probe.py
"""
import atexit
import pathlib
import re
import signal
import subprocess
import sys
import time

#: Whatever happens -- a timeout, a kill -- the tree goes back as it was.
_ORIGINALS: dict[pathlib.Path, str] = {}


def _restore(*_):
    for path, text in _ORIGINALS.items():
        path.write_text(text)
    _ORIGINALS.clear()


def _restore_and_exit(*_):
    _restore()
    sys.exit(130)


atexit.register(_restore)
for _sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(_sig, _restore_and_exit)

ROOT = pathlib.Path("/home/taro/code/mockdr-oss")
BACKEND = ROOT / "backend"
PY_BIN = BACKEND / ".venv/bin/python"

# A spread of old code and code written this week.
TARGETS = [
    "utils/pagination.py", "utils/filtering.py",
    "application/threats/queries.py", "application/mde_machines/queries.py",
    "api/documented_body.py", "api/middleware/splunk_paging.py",
    "api/middleware/date_header.py", "application/sentinel/commands/edr_bridge.py",
    "application/graph/teams/queries.py", "utils/graph_response.py",
]

#: Mutations that change behaviour a client can see, not just style.
RULES = [
    (re.compile(r"(?<![=!<>])==(?!=)"), "!="),
    (re.compile(r"\bis not None\b"), "is None"),
    (re.compile(r"(?<![\w.])True(?![\w])"), "False"),
    (re.compile(r"(?<![\w.])<=(?![\w])"), "<"),
    (re.compile(r"(?<![\w.])>=(?![\w])"), ">"),
]

def sites(path):
    text = path.read_text()
    out = []
    for line_no, line in enumerate(text.split("\n"), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or '"""' in line:
            continue
        for pattern, replacement in RULES:
            match = pattern.search(line)
            if match:
                out.append((line_no, match.start(), match.group(), replacement, line.strip()[:70]))
                break
    return out

def run_gates():
    """The fastest honest oracle: the whole backend suite, stopping at the first failure."""
    proc = subprocess.run(
        [str(PY_BIN), "-m", "pytest", "-x", "-q", "--no-cov", "-p", "no:cacheprovider", "-n", "8"],
        cwd=BACKEND, capture_output=True, text=True, timeout=1800)
    return proc.returncode != 0

caught = survived = 0
survivors = []
for rel in TARGETS:
    path = BACKEND / rel
    found = sites(path)
    if not found:
        print(f"  {rel}: no mutable site found")
        continue
    line_no, _, was, now, source = found[len(found) // 2]
    original = path.read_text()
    _ORIGINALS[path] = original
    lines = original.split("\n")
    lines[line_no - 1] = lines[line_no - 1].replace(was, now, 1)
    path.write_text("\n".join(lines))
    started = time.time()
    try:
        noticed = run_gates()
    finally:
        path.write_text(original)
        _ORIGINALS.pop(path, None)
    took = time.time() - started
    mark = "caught " if noticed else "SURVIVED"
    print(f"  {mark} {rel}:{line_no}  {was} -> {now}   ({took:.0f}s)  {source}", flush=True)
    if noticed:
        caught += 1
    else:
        survived += 1
        survivors.append(f"{rel}:{line_no}  {was}->{now}  {source}")

print(f"\n  {caught} of {caught + survived} injected defects were caught")
for s in survivors:
    print(f"    SURVIVED  {s}")
