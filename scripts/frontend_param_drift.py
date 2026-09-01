#!/usr/bin/env python3
"""Ask whether the query parameters the console sends are ones a route reads.

A parameter a route does not declare is dropped in silence. The list still
answers 200 and still returns rows -- just not the filtered, sorted or paged
ones the console asked for, which is a filter that looks like it works and
does nothing. Neither the type checker nor a mocked unit test can see it:
the call is well typed, the promise resolves, the rows arrive.

`frontend_route_drift.py` asks whether the path exists and
`frontend_body_drift.py` whether a write body's members are documented. This
asks the third: for every `<name>Api.<method>({...})` written in a view or a
store, resolve the method to the route it calls and compare the literal's
keys against the parameters that route declares.

Only literals written at the call site can be read, and only methods whose
path is written literally in `src/api/*.ts`; anything else is named as out
of reach rather than counted as a pass.
"""
from __future__ import annotations

import logging
import re
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API_DIR = ROOT / "frontend" / "src" / "api"

sys.path.insert(0, str(ROOT / "backend"))
logging.disable(logging.CRITICAL)
warnings.filterwarnings("ignore")
from main import app  # noqa: E402

#: Each axios client and the mount its paths hang off.
CLIENT_PREFIX = {
    "client": "/web/api/v2.1", "csClient": "/cs", "mdeClient": "/mde",
    "graphClient": "/graph", "sentinelClient": "/sentinel",
    "xdrClient": "/xdr/public_api/v1", "splunkClient": "/splunk",
    "esClient": "/elastic", "kbnClient": "/kibana",
}

#: `export const threatsApi = {` opens a block of methods.
_MODULE = re.compile(r"export const (?P<api>\w+Api)\s*=\s*\{")
#: `list: (params) => client.get('/threats', ...)` inside such a block.
_METHOD = re.compile(
    r"^\s{2}(?P<method>\w+):[^\n]*\n?[^\n]*?(?P<client>\w*[Cc]lient)\.get\("
    r"\s*[`'\"](?P<path>[^`'\"]+)[`'\"]",
    re.MULTILINE,
)
#: `threatsApi.list({` at a call site.
_CALL = re.compile(r"\b(?P<api>\w+Api)\.(?P<method>\w+)\(\s*\{")
_HOLE = re.compile(r"\$\{[^}]*\}|\{[^}]*\}")
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def literal_keys(text: str, brace: int) -> list[str] | None:
    """Top-level keys of the object literal starting at ``brace``."""
    depth, i, keys, key = 0, brace, [], ""
    while i < len(text):
        char = text[i]
        if char in "{[(":
            depth += 1
            if depth == 1:
                key = ""
        elif char in "}])":
            depth -= 1
            if depth == 0:
                if key.strip():
                    keys.append(key.strip())
                return keys
        elif depth == 1:
            if char == ",":
                if key.strip():
                    keys.append(key.strip())
                key = ""
            elif char == ":":
                keys.append(key.strip())
                # Skip this key's value. A comma inside a string or a
                # nested literal is part of the value, not a separator --
                # reading `$select: 'a,b,c'` as three keys is how a probe
                # invents findings.
                key, inner, quote = "", 0, ""
                i += 1
                while i < len(text):
                    char = text[i]
                    if quote:
                        if char == "\\":
                            i += 2
                            continue
                        if char == quote:
                            quote = ""
                    elif char in "'\"`":
                        quote = char
                    elif char in "{[(":
                        inner += 1
                    elif char in "}])":
                        if inner == 0:
                            i -= 1
                            break
                        inner -= 1
                    elif char == "," and inner == 0:
                        break
                    i += 1
                continue
            else:
                key += char
        i += 1
    return None


def shape(path: str) -> str:
    """The path with its parameters blanked, so two spellings can meet."""
    return _HOLE.sub("*", path).rstrip("/") or "/"


def routes() -> dict[str, set[str]]:
    """Every GET route the mock serves, by shape, with the parameters it reads."""
    declared: dict[str, set[str]] = {}
    for path, operations in app.openapi()["paths"].items():
        get = operations.get("get")
        if not get:
            continue
        names = {p["name"] for p in get.get("parameters", []) if p.get("in") == "query"}
        declared.setdefault(shape(path), set()).update(names)
    return declared


def api_methods() -> dict[tuple[str, str], str]:
    """``(apiName, method)`` → the full path it GETs, where that is literal."""
    found: dict[tuple[str, str], str] = {}
    for source in sorted(API_DIR.glob("*.ts")):
        text = _COMMENT.sub(lambda m: " " * len(m.group()), source.read_text())
        blocks = [(m.group("api"), m.end()) for m in _MODULE.finditer(text)]
        for index, (api, start) in enumerate(blocks):
            end = blocks[index + 1][1] if index + 1 < len(blocks) else len(text)
            for match in _METHOD.finditer(text[start:end]):
                prefix = CLIENT_PREFIX.get(match.group("client"))
                if prefix:
                    found[(api, match.group("method"))] = prefix + match.group("path")
    return found


def main() -> int:
    """Compare every parameter literal the console writes with what is read."""
    declared, methods = routes(), api_methods()
    findings: list[str] = []
    unreachable: list[str] = []
    checked = 0

    sources = [p for folder in ("views", "stores")
               for p in (ROOT / "frontend" / "src" / folder).rglob("*")
               if p.suffix in {".vue", ".ts"} and "__tests__" not in p.parts]

    for source in sorted(sources):
        text = _COMMENT.sub(lambda m: " " * len(m.group()), source.read_text())
        for match in _CALL.finditer(text):
            key = (match.group("api"), match.group("method"))
            where = f"{source.name}: {key[0]}.{key[1]}"
            path = methods.get(key)
            if path is None:
                continue  # A write, or a path this script cannot read.
            reads = declared.get(shape(path))
            if reads is None:
                unreachable.append(f"{where} - {path} is not a GET the mock serves")
                continue
            keys = literal_keys(text, match.end() - 1)
            if keys is None:
                unreachable.append(f"{where} - unreadable literal")
                continue

            checked += 1
            unknown = [k for k in keys if k and not k.startswith("...") and k not in reads]
            if unknown:
                findings.append(f"{where} → {path}: {', '.join(unknown)}")

    print(f"=== FRONTEND PARAM DRIFT === {checked} parameter literal(s) compared")
    print()
    for line in findings:
        print(f"  {line}")
    print(f"  {len(findings)} call(s) sending a parameter the route does not read")
    if unreachable:
        print(f"  {len(unreachable)} call(s) this script could not compare:")
        for line in sorted(set(unreachable)):
            print(f"    {line}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
