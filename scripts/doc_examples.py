# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, S101, T201
# A release tool, not library code: every function is local to this file and
# sys.path is set before the project imports on purpose.
"""Run the examples the documentation prints, and fail when one does not work.

A README is the first client a mock has, and the only one nobody tests. 2.6.0
changed status codes, defaults and token rules across all eight mounts; the
curl lines written before it kept printing the old behaviour, and the first
person to paste one met a 400 that the page said would be a 200.

Every fenced block in the documentation is classified by its language:

* ``bash`` / ``sh`` / ``shell`` blocks that call ``curl`` are **run**. A small
  interpreter covers the subset the docs use -- assignments, ``$(...)``,
  pipes into ``jq -r .path`` or ``python3 -c``, ``> file`` and ``-d @file``
  -- and sends each curl request to the mock. Each block starts with an
  empty environment and a freshly reset mock, so an example that leans on a
  variable set three sections earlier fails here the way it fails for a
  reader who scrolled straight to it.
* ``spl`` blocks are run query by query through Splunk's export endpoint,
  ``kql`` blocks line by line through the Log Analytics query endpoint: a
  query the page offers as working has to parse and run.
* ``json`` blocks must parse. ``python`` blocks must compile -- they show
  internals and are not executed; the public client they describe is
  exercised by ``backend/tests/unit/test_testing_module.py``.
* Other languages (yaml, typescript, javascript, unlabelled text) are not
  requests and are counted, not run.

A shell block that is not runnable here -- install steps, ``docker``, a
command for a real product -- must say so, with an HTML comment on the line
before the fence::

    <!-- doc-examples: skip installs dependencies; see the clean-clone check -->

An unmarked shell block that is not runnable is a failure, so nothing is
skipped silently. A block that goes on from the one before it -- the token
fetched there, used here -- says so with ``<!-- doc-examples: continue -->``
and starts with that block's variables, as in the reader's terminal.

What a request must answer:

* below 400, unless the block says otherwise in a comment -- ``# → 403``
  after the command, or a comment naming a status (``# 400, ...``,
  ``# Users: 200 OK``) before the commands it applies to (until the next
  blank line or comment);
* a JSON content type must carry JSON that parses;
* a comment directly after the command of the form ``# hits.total.value: 0``
  or ``# Response includes: "@odata.count": 66`` is checked against the
  response body (dotted path, JSON value).

By default every request is served in-process through FastAPI's TestClient,
so this needs no running server and gates CI. ``--base-url`` sends the same
requests to a live instance instead -- the URL in the docs (``localhost:8001``,
``localhost:5001``) is rewritten to it.

    backend/.venv/bin/python scripts/doc_examples.py [-v] [--base-url URL] [FILE ...]

Exit status 1 when any example fails.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import httpx

#: The pages a reader is sent to. CHANGELOG is history, LICENSE/CLA are
#: legal text, team/ is internal process -- none of them promise behaviour.
DOCS = [
    "README.md",
    "TESTING.md",
    "CONTRIBUTING.md",
    "ARCHITECTURE.md",
    "SECURITY.md",
    "docs/*.md",
    "docs/adr/*.md",
    "toolkit/SETUP_GUIDE.md",
    "scripts/README.md",
    "conformance/README.md",
]

SHELL = {"bash", "sh", "shell", "console", "zsh"}
PASSIVE = {"", "text", "yaml", "yml", "typescript", "ts", "javascript", "js", "toml", "ini"}

#: Hosts the docs use for "the mock". Anything else is a real product, and a
#: request to it would leave this machine.
MOCK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "<host>", "mockdr"}  # noqa: S104

ADMIN_S1 = {"Authorization": "ApiToken admin-token-0000-0000-000000000001"}

#: --show: print every exchange, for writing a new example.
SHOW = False

FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})\s*([\w+-]*)\s*$")
MARKER = re.compile(r"^\s*<!--\s*doc-examples:\s*(\w+)\s*(.*?)\s*-->\s*$")
STATUS_AFTER = re.compile(r"^#\s*→\s*([1-5]\d\d)\b")
STATUS_BEFORE = re.compile(r"\b([1-5]\d\d)(?:,|\s+[A-Z][A-Za-z]+\b)")
ASSERT_PATH = re.compile(
    r'^#\s*(?:Response includes:\s*)?"?([A-Za-z_@$][\w.@$-]*)"?\s*:\s*(.+?)\s*$',
)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

@dataclass
class Block:
    """One fenced block, with the marker on the line before it."""

    path: str
    line: int
    lang: str
    text: str
    marker: tuple[str, str] | None


def blocks(path: Path):
    lines = path.read_text(encoding="utf-8").splitlines()
    i = 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        indent, fence, lang = m.groups()
        start = i
        body = []
        i += 1
        while i < len(lines) and not lines[i].strip().startswith(fence):
            body.append(lines[i][len(indent):] if lines[i].startswith(indent) else lines[i])
            i += 1
        i += 1
        marker = None
        j = start - 1
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j >= 0 and (mm := MARKER.match(lines[j])):
            marker = (mm.group(1), mm.group(2))
        yield Block(str(path.relative_to(ROOT)), start + 1, lang.lower(), "\n".join(body), marker)


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

class Mock:
    """Sends a request to the mock, in-process or over the network."""

    def __init__(self, base_url: str | None) -> None:
        """Talk to ``base_url``, or to the app in this process when it is None."""
        if base_url:
            self.client: httpx.Client = httpx.Client(base_url=base_url.rstrip("/"), timeout=30)
            self.prefix = base_url.rstrip("/")
        else:
            from fastapi.testclient import TestClient
            from main import app

            self.client = TestClient(app, raise_server_exceptions=False).__enter__()
            self.prefix = "http://testserver"

    def request(self, method, path_query, headers, body):
        """Send one request; ``path_query`` is relative to the mock's root."""
        return self.client.request(
            method, self.prefix + path_query, headers=headers, content=body,
        )

    def restore(self) -> None:
        """Put back what an example may have changed, so the next one starts clean."""
        base = "/web/api/v2.1/_dev"
        self.request("POST", f"{base}/proxy/config",
                     {**ADMIN_S1, "Content-Type": "application/json"}, b'{"mode": "off"}')
        self.request("POST", f"{base}/rate-limit",
                     {**ADMIN_S1, "Content-Type": "application/json"}, b'{"enabled": false}')
        self.request("DELETE", f"{base}/fault-injection", ADMIN_S1, None)
        reset = self.request("POST", f"{base}/reset", ADMIN_S1, None)
        if reset.status_code != 200:
            raise SystemExit(f"cannot reset the mock between examples: {reset.status_code}")


# ---------------------------------------------------------------------------
# A small shell
# ---------------------------------------------------------------------------

class ShellError(Exception):
    """A block uses something this interpreter cannot (or must not) run."""


@dataclass
class Exchange:
    """A request an example sent, its answer, and what the doc says of it."""

    method: str
    url: str
    status: int
    content_type: str
    text: str
    expect: int | None = None
    asserts: list[tuple[str, str]] = field(default_factory=list)


class Op(str):
    """An operator token (``|``, ``>``, ``&&``, ``;``)."""


def logical_lines(text: str):
    """Join continuations and quoted newlines; yield each logical line."""
    buf = ""
    for raw in text.splitlines():
        buf = f"{buf}\n{raw}" if buf else raw
        if buf.endswith("\\") and not _open_quote(buf[:-1]):
            buf = buf[:-1]
            continue
        if _open_quote(buf):
            continue
        yield buf
        buf = ""
    if buf:
        yield buf


def _open_quote(s: str) -> str | None:
    quote_char = None
    i = 0
    while i < len(s):
        c = s[i]
        if quote_char == "'":
            if c == "'":
                quote_char = None
        elif quote_char == '"':
            if c == "\\":
                i += 1
            elif c == '"':
                quote_char = None
        elif c == "\\":
            i += 1
        elif c in "'\"":
            quote_char = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return None
        i += 1
    return quote_char


class Shell:
    """The subset of bash the documentation's examples are written in."""

    def __init__(self, mock: Mock, workdir: Path) -> None:
        """Run against ``mock``; ``> file`` and ``@file`` resolve in ``workdir``."""
        self.mock = mock
        self.workdir = workdir
        self.env: dict[str, str] = {}
        self.exchanges: list[Exchange] = []

    # -- words ---------------------------------------------------------------

    def words(self, line: str) -> list[str]:
        """Split a line into words and operators, expanding as bash would."""
        out: list[str] = []
        cur: list[str] = []
        have = False
        i = 0

        def flush():
            nonlocal cur, have
            if have:
                out.append("".join(cur))
            cur, have = [], False

        while i < len(line):
            c = line[i]
            if c in " \t\n":
                flush()
                i += 1
            elif c == "#" and not have:
                break
            elif c in "|;&>":
                flush()
                two = line[i:i + 2]
                if two in ("&&", "||", ">>"):
                    out.append(Op(two))
                    i += 2
                else:
                    out.append(Op(c))
                    i += 1
            elif c == "'":
                j = line.index("'", i + 1)
                cur.append(line[i + 1:j])
                have = True
                i = j + 1
            elif c == '"':
                i += 1
                have = True
                while line[i] != '"':
                    if line[i] == "\\" and line[i + 1] in '"\\$`':
                        cur.append(line[i + 1])
                        i += 2
                    elif line[i] == "$":
                        value, i = self.expand(line, i)
                        cur.append(value)
                    else:
                        cur.append(line[i])
                        i += 1
                i += 1
            elif c == "\\":
                cur.append(line[i + 1])
                have = True
                i += 2
            elif c == "$":
                value, i = self.expand(line, i)
                cur.append(value)
                have = True
            else:
                cur.append(c)
                have = True
                i += 1
        flush()
        return out

    def expand(self, line: str, i: int) -> tuple[str, int]:
        """Expand the ``$`` at ``line[i]``; return the value and where it ends."""
        if line.startswith("$(", i):
            depth, j, q = 1, i + 2, None
            while depth:
                c = line[j]
                if q:
                    if c == q:
                        q = None
                    elif c == "\\" and q == '"':
                        j += 1
                elif c in "'\"":
                    q = c
                elif c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                j += 1
            return self.run_line(line[i + 2:j - 1], capture=True).rstrip("\n"), j
        m = re.compile(r"\$(?:\{(\w+)\}|(\w+))").match(line, i)
        if not m:
            return "$", i + 1
        name = m.group(1) or m.group(2)
        if name not in self.env:
            raise ShellError(f"uses ${name}, which nothing in the block sets")
        return self.env[name], m.end()

    # -- commands ------------------------------------------------------------

    def run_line(self, line: str, capture: bool = False) -> str:
        """Run one logical line; return its output when ``capture`` is set."""
        words = self.words(line)
        if not words:
            return ""
        if (
            len(words) == 1 and not isinstance(words[0], Op)
            and re.match(r"^[A-Za-z_]\w*=", words[0])
        ):
            name, _, value = words[0].partition("=")
            self.env[name] = value
            return ""
        out = ""
        seq: list[list[str]] = [[]]
        for w in words:
            if isinstance(w, Op) and w in ("&&", ";"):
                seq.append([])
            else:
                seq[-1].append(w)
        for cmd in seq:
            if cmd:
                out += self.pipeline(cmd)
        if capture:
            return out
        return ""

    def pipeline(self, words: list[str]) -> str:
        """Run ``a | b | c [> file]``; return what the last stage printed."""
        redirect = None
        if len(words) >= 2 and words[-2] in (">", ">>") and isinstance(words[-2], Op):
            redirect = words[-1]
            words = words[:-2]
        stages: list[list[str]] = [[]]
        for w in words:
            if isinstance(w, Op) and w == "|":
                stages.append([])
            elif isinstance(w, Op):
                raise ShellError(f"operator {w!r} is not supported")
            else:
                stages[-1].append(w)
        data = ""
        for stage in stages:
            data = self.command(stage, data)
        if redirect is not None:
            (self.workdir / redirect).write_text(data, encoding="utf-8")
            return ""
        return data

    def command(self, argv: list[str], stdin: str) -> str:
        """Run one command of a pipeline, fed ``stdin``."""
        name = argv[0]
        if name == "curl":
            return self.curl(argv[1:])
        if name == "jq":
            return self.jq(argv[1:], stdin)
        if name in ("python3", "python") and len(argv) >= 3 and argv[1] == "-c":
            return self.subprocess([sys.executable, *argv[1:]], stdin)
        if name == "date" or name == "echo":
            return self.subprocess(argv, stdin)
        raise ShellError(f"runs {name!r}, which this harness does not run -- mark the block")

    def subprocess(self, argv: list[str], stdin: str) -> str:
        """Run a helper the examples call (``python3 -c``, ``date``) for real."""
        proc = subprocess.run(  # noqa: S603 - the docs' own commands, no shell
            argv, input=stdin, capture_output=True, text=True, timeout=30,
            cwd=self.workdir, check=False,
        )
        if proc.returncode != 0:
            raise ShellError(f"{argv[0]} failed: {proc.stderr.strip()[-300:]}")
        return proc.stdout

    @staticmethod
    def jq(args: list[str], stdin: str) -> str:
        """The one jq form the docs use: ``jq [-r] .path``."""
        flags = [a for a in args if a.startswith("-")]
        exprs = [a for a in args if not a.startswith("-")]
        if len(exprs) != 1 or set(flags) - {"-r"}:
            raise ShellError(f"jq {' '.join(args)} is beyond the jq subset here")
        path = re.sub(r"\[(\d+)\]", r".\1", exprs[0]).lstrip(".")
        if not re.fullmatch(r"[\w@$.-]*", path):
            raise ShellError(f"jq {exprs[0]} is beyond the jq subset here")
        value = _dig(json.loads(stdin), path)
        if "-r" in flags and isinstance(value, str):
            return value + "\n"
        return json.dumps(value) + "\n"

    def curl(self, args: list[str]) -> str:
        """Send a curl command line to the mock; return the body it answered."""
        method = None
        headers: dict[str, str] = {}
        data: list[str] = []
        url = None
        get = False
        i = 0
        no_value = {"-s", "-S", "-f", "-i", "-k", "-L", "-v", "--silent", "--show-error",
                    "--fail", "--compressed", "--location", "--insecure"}
        with_value_ignored = {"--retry", "--retry-delay", "--max-time", "-m", "-o", "-w",
                              "--connect-timeout"}
        while i < len(args):
            a = args[i]
            if a in ("-X", "--request"):
                method = args[i + 1]
                i += 2
            elif a.startswith("-X") and len(a) > 2:
                method = a[2:]
                i += 1
            elif a in ("-H", "--header"):
                k, _, v = args[i + 1].partition(":")
                headers[k.strip()] = v.strip()
                i += 2
            elif a in ("-d", "--data", "--data-raw", "--data-binary"):
                value = args[i + 1]
                if value.startswith("@") and a != "--data-raw":
                    value = (self.workdir / value[1:]).read_text(encoding="utf-8")
                    if a != "--data-binary":
                        value = value.replace("\r", "").replace("\n", "")
                data.append(value)
                i += 2
            elif a == "--data-urlencode":
                k, eq, v = args[i + 1].partition("=")
                data.append(f"{k}={quote(v, safe='')}" if eq else quote(k, safe=""))
                i += 2
            elif a in ("-u", "--user"):
                token = base64.b64encode(args[i + 1].encode()).decode()
                headers["Authorization"] = f"Basic {token}"
                i += 2
            elif a in ("-G", "--get"):
                get = True
                i += 1
            elif a in ("-I", "--head"):
                method = "HEAD"
                i += 1
            elif a in no_value or re.fullmatch(r"-[sSfikLv]+", a):
                i += 1
            elif a in with_value_ignored:
                i += 2
            elif a.startswith("-"):
                raise ShellError(f"curl option {a} is not supported")
            else:
                url = a
                i += 1
        if url is None:
            raise ShellError("curl without a URL")
        if "://" not in url:
            url = "http://" + url
        parts = urlsplit(url)
        if parts.hostname not in MOCK_HOSTS and not url.startswith("http://<host>"):
            raise ShellError(f"would send a request to {parts.netloc}, which is not the mock")
        path_query = url.split(parts.netloc, 1)[1] or "/"
        body = None
        if data:
            joined = "&".join(data)
            if get:
                path_query += ("&" if "?" in path_query else "?") + joined
            else:
                body = joined.encode()
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if method is None:
            method = "POST" if body is not None else "GET"
        response = self.mock.request(method, path_query, headers, body)
        if SHOW:
            print(f"     > {method} {path_query[:100]} -> {response.status_code} "
                  f"{response.text[:300]!r}")
        self.exchanges.append(Exchange(
            method, path_query, response.status_code,
            response.headers.get("content-type", ""), response.text,
        ))
        return response.text


def _dig(value, path: str):
    """Follow a dotted path; a key that itself has dots (``@odata.count``) wins."""
    parts = [p for p in path.split(".") if p]
    while parts:
        if isinstance(value, list) and parts[0].isdigit() and int(parts[0]) < len(value):
            value = value[int(parts.pop(0))]
            continue
        if not isinstance(value, dict):
            return None
        for n in range(len(parts), 0, -1):
            key = ".".join(parts[:n])
            if key in value:
                value = value[key]
                parts = parts[n:]
                break
        else:
            return None
    return value


# ---------------------------------------------------------------------------
# Block runners
# ---------------------------------------------------------------------------

def run_shell(block: Block, mock: Mock, env: dict[str, str]) -> list[str]:
    """Run one shell block; ``env`` is what it starts with, and is updated in place."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        shell = Shell(mock, Path(tmp))
        shell.env = env
        pending: int | None = None
        last_was_command = False
        for line in logical_lines(block.text):
            stripped = line.strip()
            if not stripped:
                pending = None
                last_was_command = False
                continue
            if stripped.startswith("#"):
                if last_was_command and shell.exchanges:
                    if m := STATUS_AFTER.match(stripped):
                        shell.exchanges[-1].expect = int(m.group(1))
                        continue
                    m = ASSERT_PATH.match(stripped)
                    if m and _is_json(m.group(2)):
                        shell.exchanges[-1].asserts.append((m.group(1), m.group(2)))
                        continue
                m = STATUS_BEFORE.search(stripped)
                pending = int(m.group(1)) if m else None
                last_was_command = False
                continue
            before = len(shell.exchanges)
            try:
                shell.run_line(line)
            except ShellError as exc:
                problems.append(f"{stripped.splitlines()[0][:70]}: {exc}")
                break
            for ex in shell.exchanges[before:]:
                ex.expect = pending
            last_was_command = True
        for ex in shell.exchanges:
            problems.extend(judge(ex))
        if not shell.exchanges and not problems:
            problems.append("sent no request")
    return problems


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def judge(ex: Exchange) -> list[str]:
    where = f"{ex.method} {ex.url[:90]}"
    out = []
    if ex.expect is not None:
        if ex.status != ex.expect:
            out.append(f"{where}: {ex.status}, the doc says {ex.expect} -- {ex.text[:160]}")
    elif ex.status >= 400:
        out.append(f"{where}: {ex.status} -- {ex.text[:200]}")
    body = None
    if "json" in ex.content_type:
        try:
            body = json.loads(ex.text) if ex.text else None
        except ValueError:
            # Splunk's export streams one JSON object per line under the same
            # content type, as splunkd does.
            try:
                body = [json.loads(x) for x in ex.text.splitlines() if x.strip()]
            except ValueError:
                out.append(f"{where}: says JSON and is not")
    for path, expected in ex.asserts:
        got = _dig(body, path)
        if got != json.loads(expected):
            out.append(f"{where}: {path} is {got!r}, the doc says {expected}")
    return out


def _token(mock: Mock, path: str, form: str) -> str:
    r = mock.request("POST", path, {"Content-Type": "application/x-www-form-urlencoded"},
                     form.encode())
    return str(r.json().get("access_token", ""))


def run_spl(block: Block, mock: Mock) -> list[str]:
    problems = []
    queries: list[str] = []
    for line in block.text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            if queries and queries[-1]:
                queries.append("")
            continue
        if queries and queries[-1] and s.startswith("|"):
            queries[-1] += " " + s
        elif queries and not queries[-1]:
            queries[-1] = s
        else:
            queries.append(s)
    auth = "Basic " + base64.b64encode(b"admin:mockdr-admin").decode()
    for q in [q for q in queries if q]:
        body = f"search={quote(q, safe='')}&output_mode=json".encode()
        r = mock.request("POST", "/splunk/services/search/jobs/export",
                         {"Authorization": auth,
                          "Content-Type": "application/x-www-form-urlencoded"}, body)
        rows = [json.loads(x) for x in r.text.splitlines() if x.strip()]
        messages = [m for row in rows for m in row.get("messages", [])
                    if m.get("type") in ("ERROR", "FATAL")]
        results = [row for row in rows if "result" in row]
        if r.status_code >= 400 or messages:
            problems.append(f"{q[:80]}: {r.status_code} {messages or r.text[:160]}")
        elif not results:
            problems.append(f"{q[:80]}: runs, and returns nothing from the seed")
    return problems


def run_kql(block: Block, mock: Mock) -> list[str]:
    token = _token(
        mock, "/sentinel/oauth2/v2.0/token",
        "client_id=sentinel-mock-client-id&client_secret=sentinel-mock-client-secret"
        "&grant_type=client_credentials&scope=https%3A%2F%2Fapi.loganalytics.io%2F.default",
    )
    problems = []
    for q in [s.strip() for s in block.text.splitlines() if s.strip()]:
        r = mock.request(
            "POST", "/sentinel/v1/workspaces/mockdr-workspace/query",
            {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json.dumps({"query": q}).encode(),
        )
        if r.status_code >= 400:
            problems.append(f"{q[:80]}: {r.status_code} {r.text[:160]}")
        elif not any(t.get("rows") for t in r.json().get("tables", [])):
            problems.append(f"{q[:80]}: runs, and returns nothing from the seed")
    return problems


def run_block(block: Block, mock: Mock, env: dict[str, str]) -> tuple[str, list[str]]:
    """Return (outcome, problems); outcome is run, skip, passive, compiled or parsed.

    ``env`` carries the variables of the page's previous shell block, for a
    block marked ``continue``; every other block starts with nothing.
    """
    carry = False
    if block.marker:
        kind, reason = block.marker
        if kind == "continue":
            carry = True
        elif kind != "skip":
            return "run", [f"unknown doc-examples marker {kind!r}"]
        elif not reason:
            return "run", ["a skip marker needs a reason"]
        else:
            return "skip", []
    lang = block.lang
    if lang in SHELL:
        if "curl " not in block.text:
            return "run", ["a shell block this harness cannot run -- mark it skip with a reason"]
        # A fresh mock for every block but one that continues the last: the
        # job it started and the record it created are still there for it.
        if not carry:
            env.clear()
            mock.restore()
        return "run", run_shell(block, mock, env)
    if lang == "spl":
        mock.restore()
        return "run", run_spl(block, mock)
    if lang == "kql":
        mock.restore()
        return "run", run_kql(block, mock)
    if lang == "json":
        try:
            json.loads(block.text)
        except ValueError as exc:
            return "parsed", [f"not JSON: {exc}"]
        return "parsed", []
    if lang in ("python", "py"):
        try:
            compile(block.text, f"{block.path}:{block.line}", "exec")
        except SyntaxError as exc:
            return "compiled", [f"does not compile: {exc.msg} (line {exc.lineno})"]
        return "compiled", []
    if lang in PASSIVE or lang:
        return "passive", []
    return "passive", []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="*", help="markdown files (default: the doc set)")
    parser.add_argument("--base-url", help="a live mock, e.g. http://127.0.0.1:8104")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--show", action="store_true", help="print every exchange")
    args = parser.parse_args()
    # Here rather than at import: the unit tests import this module, and a
    # process-wide logging.disable would silence every log a later test in
    # the same worker asserts on.
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings("ignore")
    global SHOW
    SHOW = args.show

    if args.files:
        paths = [Path(f).resolve() for f in args.files]
    else:
        paths = sorted({p for pattern in DOCS for p in ROOT.glob(pattern)})
    os.environ.setdefault("MOCKDR_SPLUNK_DISPATCH_SECONDS", "0")
    mock = Mock(args.base_url)

    counts: dict[str, int] = {}
    failures = 0
    for path in paths:
        env: dict[str, str] = {}
        for block in blocks(path):
            outcome, problems = run_block(block, mock, env)
            counts[outcome] = counts.get(outcome, 0) + 1
            where = f"{block.path}:{block.line} [{block.lang or 'text'}]"
            if problems:
                failures += 1
                print(f"FAIL {where}")
                for p in problems:
                    print(f"     {p}")
            elif args.verbose and outcome != "passive":
                note = f" -- {block.marker[1]}" if outcome == "skip" and block.marker else ""
                print(f"{outcome:8} {where}{note}")
    mock.restore()
    summary = ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
    print(f"\n{sum(counts.values())} blocks in {len(paths)} files: {summary}; {failures} failing")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
