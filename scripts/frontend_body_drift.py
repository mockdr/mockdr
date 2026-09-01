#!/usr/bin/env python3
"""Ask whether the members the console writes are members the vendor documents.

`frontend_type_drift.py` asks the read question: does the answer carry what
the console declares? This is the write one. A member the vendor never
documents is not refused by anything -- the route reads the members it knows
and drops the rest -- so the console posts it, gets its 200, and the field it
meant to set stays as it was. That is the same silent wrongness as a blank
column, arriving through the other door.

`DOCUMENTED_BODIES` already holds, per (vendor, method, route), every member
the vendor's own reference recognises, generated from those references. This
compares the object literals the console posts against that set.

Only literals written at the call site can be read here; a body the caller
builds and passes in is counted as out of reach and named, not passed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
from application.documented_bodies import DOCUMENTED_BODIES  # noqa: E402

#: The axios clients whose vendor has a documented-body table.
CLIENT_VENDOR = {
    "client": ("sentinelone", "/web/api/v2.1"),
    "csClient": ("crowdstrike", "/cs"),
    "xdrClient": ("xdr", "/xdr/public_api/v1"),
}

_CALL = re.compile(
    r"(?P<client>\w*[Cc]lient)\.(?P<verb>post|put|patch)\("
    r"\s*[`'\"](?P<path>[^`'\"]+)[`'\"]\s*,\s*(?P<body>\{)"
)

#: A `${...}` in the console's path, a `{...}` in the router's: both are holes.
_HOLE = re.compile(r"\$\{[^}]*\}|\{[^}]*\}")

#: Comments would otherwise be read as member names, and a spread carries
#: members the call site does not name -- both are noise, not findings.
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def literal_members(text: str, brace: int) -> list[str] | None:
    """Top-level keys of the object literal that starts at ``brace``."""
    depth, i, members, key = 0, brace, [], ""
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
                    members.append(key.strip())
                return members
        elif depth == 1:
            if char == ",":
                if key.strip():
                    members.append(key.strip())
                key = ""
            elif char == ":":
                members.append(key.strip())
                # Skip this member's value: it may hold commas of its own.
                key, inner = "", 0
                i += 1
                while i < len(text):
                    if text[i] in "{[(":
                        inner += 1
                    elif text[i] in "}])":
                        if inner == 0:
                            i -= 1
                            break
                        inner -= 1
                    elif text[i] == "," and inner == 0:
                        break
                    i += 1
                continue
            else:
                key += char
        i += 1
    return None


def shape(path: str) -> str:
    """The path with its parameters blanked, so two spellings can meet."""
    return _HOLE.sub("*", path).rstrip("/")


def main() -> int:
    """Compare every literal the console writes with the vendor's members."""
    documented: dict[tuple[str, str, str], frozenset[str]] = {
        (vendor, method, shape(route)): recognisable
        for (vendor, method, route), (_, recognisable, _) in DOCUMENTED_BODIES.items()
    }

    findings: list[str] = []
    unreachable: list[str] = []
    checked = 0

    for source in sorted((ROOT / "frontend" / "src" / "api").glob("*.ts")):
        # Blank the comments in place, so every offset still lines up.
        text = _COMMENT.sub(lambda m: " " * len(m.group()), source.read_text())
        for match in _CALL.finditer(text):
            vendor_prefix = CLIENT_VENDOR.get(match.group("client"))
            if vendor_prefix is None:
                continue
            vendor, prefix = vendor_prefix
            verb, path = match.group("verb").upper(), match.group("path")
            members = literal_members(text, match.start("body"))
            if members is None:
                unreachable.append(f"{source.stem}: {verb} {path} - unreadable literal")
                continue

            recognisable = documented.get((vendor, verb, shape(path)))
            if recognisable is None:
                unreachable.append(
                    f"{source.stem}: {verb} {prefix}{path} - no documented body for it")
                continue

            checked += 1
            spread = [m for m in members if m.startswith("...")]
            if spread:
                unreachable.append(
                    f"{source.stem}: {verb} {prefix}{path} - {len(spread)} spread(s), "
                    "whose members the call site does not name")
            unknown = [m for m in members
                       if m and not m.startswith("...") and m not in recognisable]
            if unknown:
                findings.append(
                    f"{verb} {prefix}{path}: {', '.join(unknown)} "
                    f"(documented: {', '.join(sorted(recognisable))[:70]}…)")

    print(f"=== FRONTEND BODY DRIFT === {checked} write body(ies) compared")
    print()
    for line in findings:
        print(f"  {line}")
    print(f"  {len(findings)} body(ies) writing a member the vendor does not document")
    if unreachable:
        print(f"  {len(unreachable)} call(s) this script could not compare:")
        for line in unreachable:
            print(f"    {line}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
