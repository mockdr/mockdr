# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Every route the console calls must be one the mock serves.

A view that calls a path the backend does not have gets whatever the
catch-all gives it, and renders an empty table — which reads, to whoever is
looking at the console, exactly like a quiet day. `frontend_fixture_drift.py`
already asks whether the *shapes* still match; this asks the question
underneath it, which is whether the call arrives anywhere at all.

Found on the first run:

* `mdeIndicatorsApi.get` and `.update` called `GET` and `PATCH` on
  `/api/indicators/{id}`. Defender documents five indicator operations and
  neither of those, and the mock rightly served only `DELETE` there.
* `splunkSearchApi.exportSearch` used `GET /services/search/jobs/export`.
  splunkd answers that with 405 — measured on 10.4.2 — and so does the mock.
* Three Graph calls defaulted their user to `me`, the delegated-auth
  shortcut. mockdr authenticates with client credentials throughout and the
  CSDL reference documents no `/me` operation, so the default named a path
  nothing can serve.

The check is static: it reads the call sites out of `frontend/src/api` and
compares them with `app.openapi()`. A template hole (`${...}`) usually
stands for one path segment, but not always — `${userId}` on the Graph mail
calls holds `users/<id>`, and the Sentinel ARM workspace prefix holds six —
so a call is matched against every served shape a hole could span, and only
a call that fits none of them is reported.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import logging

logging.disable(logging.CRITICAL)

from main import app  # noqa: E402

#: Each API client, and the prefix it mounts on. Read from `baseURL:` in the
#: module that defines it, so a change there cannot drift from this.
_BASE_URL = re.compile(r"baseURL:\s*'([^']+)'")
#: `xClient.get(` or `xClient.post(`, then a quoted or backticked path.
_CALL = re.compile(
    r"(\w*[Cc]lient)\.(get|post|put|patch|delete)\(\s*(`[^`]*`|'[^']*')")
#: A `${...}` hole, and a `{name}` path parameter.
_HOLE = re.compile(r"\$\{[^}]*\}")
_PARAM = re.compile(r"\{[^}]*\}")

#: Template holes that stand for a whole path, not one segment. Each is a
#: constant in the module that uses it, and its value is spliced in before
#: the comparison.
_MULTI_SEGMENT = {
    "WS_PREFIX": (
        "/subscriptions/{}/resourceGroups/{}/providers"
        "/Microsoft.OperationalInsights/workspaces/{}"
        "/providers/Microsoft.SecurityInsights"
    ),
}


def clients(api_dir: Path) -> dict[str, str]:
    """Every client's base path, by the variable that declares it."""
    bases: dict[str, str] = {}
    for path in sorted(api_dir.glob("*.ts")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(
            r"(?:export )?const (\w+)\s*=\s*[^;]*?baseURL:\s*'([^']+)'", text, re.S,
        ):
            bases[match.group(1)] = match.group(2)
    return bases


def call_sites(api_dir: Path):
    """(verb, path, file) for every client call in the api layer."""
    for path in sorted(api_dir.glob("*.ts")):
        text = path.read_text(encoding="utf-8")
        for match in _CALL.finditer(text):
            client, verb, raw = match.groups()
            yield client, verb.upper(), raw[1:-1], path.name


def shape(path: str) -> str:
    """A path with every parameter anonymised, so names cannot differ."""
    return _PARAM.sub("{}", path.split("?")[0].rstrip("/")) or "/"


def served() -> dict[str, set[str]]:
    """Every path shape the mock serves, and the verbs it takes there."""
    out: dict[str, set[str]] = {}
    for path, methods in app.openapi()["paths"].items():
        out.setdefault(shape(path), set()).update(m.upper() for m in methods)
    return out


def resolved(raw: str) -> str:
    """The call's path with its template holes filled in."""
    for name, value in _MULTI_SEGMENT.items():
        raw = raw.replace("${" + name + "}", value)
    return _HOLE.sub("{}", raw)


def matches(call: str, served: str) -> bool:
    """Whether `call` can be `served`, letting each hole span >= 1 segment.

    `/v1.0/{}/messages` fits `/v1.0/users/{}/messages`: the hole holds
    `users/<id>`, which is two segments and one variable.
    """
    if call == served:
        return True
    pattern = "^" + r"[^/]+(?:/[^/]+)*".join(
        re.escape(part) for part in call.split("{}")) + "$"
    return re.match(pattern, served) is not None


def main() -> int:
    api_dir = ROOT / "frontend" / "src" / "api"
    bases = clients(api_dir)
    known = served()

    reached = 0
    misses: list[tuple[str, str, str, str]] = []
    for client, verb, raw, file in call_sites(api_dir):
        base = bases.get(client)
        if base is None:
            continue
        path = resolved(raw)
        full = shape(base + ("" if path.startswith("/") else "/") + path)
        verbs = known.get(full)
        if verbs is None and "{}" in full:
            # The hole may hold more than one segment.
            for candidate, taken in known.items():
                if matches(full, candidate):
                    verbs = taken
                    break
        if verbs is None:
            misses.append((verb, full, file, "no such route"))
        elif verb not in verbs:
            misses.append(
                (verb, full, file, f"serves {','.join(sorted(verbs))}"))
        else:
            reached += 1

    print(f"=== FRONTEND ROUTES === {reached + len(misses)} call site(s) read")
    for verb, path, file, why in sorted(set(misses), key=lambda m: m[1]):
        print(f"  {verb:<7} {path:<60} {why}  ({file})")
    print(f"\n  {len(misses)} call(s) the mock does not serve")
    return 1 if misses else 0


if __name__ == "__main__":
    raise SystemExit(main())
