# ruff: noqa: ANN001, ANN201, ANN202, D103, E402, PLR0912, PLR2004
"""Reduce the Defender for Endpoint API docs into a route → shape map.

Microsoft publishes no machine-readable spec for the MDE API, but the docs
are versioned as Markdown in ``github.com/MicrosoftDocs/defender-docs``
(``defender-endpoint/api/*.md``): each API page carries a ``## HTTP request``
block and JSON response examples; each entity page a ``## Properties`` table.
This walks them and writes ``data/vendor-specs/mde_docs_reduced.json``:

    {"routes": {"GET /api/alerts": {"page": "get-alerts.md",
                 "paths": ["value", "value[*].id", ...]}},
     "entities": {"alerts": ["id", "title", ...]}}

    git clone --depth 1 --filter=blob:none --sparse \\
        https://github.com/MicrosoftDocs/defender-docs /tmp/defender-docs
    (cd /tmp/defender-docs && git sparse-checkout set defender-endpoint/api)
    backend/.venv/bin/python scripts/mde_docs_spec.py /tmp/defender-docs
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "vendor-specs" / "mde_docs_reduced.json"

_REQUEST = re.compile(r"## HTTP request.*?```[A-Za-z]*\n(.*?)```", re.S)
# a path may carry spaces inside its placeholder: {machine action id}
_VERB = re.compile(
    r"^(GET|POST|PATCH|PUT|DELETE)\s+(\S[^\n]*?)\s*$", re.M | re.I
)  # "Delete https://…"
# Fences vary: ```json, ```JSON, or bare ``` in a response section.
_JSON_BLOCK = re.compile(r"```(?:json|JSON|http|HTTP)?[^\n]*\n(.*?)```", re.S)
_PROPS = re.compile(r"## Properties[^\n]*\n\s*(\|.*?)(?:\n\n|\n##|\Z)", re.S)


def observed(value, prefix: str = "", depth: int = 0) -> set[str]:
    out: set[str] = set()
    if depth > 8:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            out.add(f"{prefix}{k}")
            out |= observed(v, f"{prefix}{k}.", depth + 1)
    elif isinstance(value, list):
        for item in value[:5]:
            out |= observed(item, f"{prefix[:-1]}[*]." if prefix else "[*].", depth + 1)
    return out


def _json_blocks(text: str) -> list:
    """Parse the example blocks; the docs elide with ``...`` and add comments."""
    blocks = []
    for raw in _JSON_BLOCK.findall(text):
        # An ```http block carries "HTTP/1.1 200 OK" and headers before the body.
        lines = raw.splitlines()
        while lines and not lines[0].lstrip().startswith(("{", "[")):
            lines.pop(0)
        if not lines:
            continue
        raw = "\n".join(lines)
        cleaned = re.sub(r"//.*", "", raw)
        cleaned = re.sub(r"^\s*(\.\.\.|…)\s*,?\s*$", "", cleaned, flags=re.M)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        try:
            blocks.append(json.loads(cleaned))
        except json.JSONDecodeError:
            blocks.append(_key_tree(cleaned))
    return blocks


def _key_tree(text: str):
    """A best-effort object from an example that is not valid JSON.

    The docs' examples are pretty-printed one key per line, so a line-wise
    walk recovers every ``"key":`` with its nesting even when a value was
    elided or a comma is missing.
    """
    root: dict = {}
    containers: list = [root]
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'"([^"]+)"\s*:\s*(.*)$', line)
        if m:
            key, rest = m.groups()
            cur = containers[-1]
            if not isinstance(cur, dict):
                continue
            if rest.startswith("{"):
                cur[key] = {}
                if not re.search(r"\}\s*,?\s*$", rest) or rest.count("{") > rest.count("}"):
                    containers.append(cur[key])
            elif rest.startswith("["):
                cur[key] = []
                if not re.search(r"\]\s*,?\s*$", rest) or rest.count("[") > rest.count("]"):
                    containers.append(cur[key])
            else:
                cur[key] = ""
            continue
        if line.startswith("{"):
            if isinstance(containers[-1], list):
                item: dict = {}
                containers[-1].append(item)
                containers.append(item)
            continue
        if line.startswith(("}", "]")) and len(containers) > 1:
            containers.pop()
    return root


def _route(path: str) -> str:
    """Normalise ``/api/alerts/{id}`` and ``/api/alerts/123`` alike."""
    path = path.split("?")[0]
    path = re.sub(r"https?://[^/]+", "", path)
    path = re.sub(r"<[^>]+>", "{id}", path)  # <machineactionid>
    return re.sub(r"\{[^}]+\}", "{id}", path)


def main(repo: Path) -> int:
    pages = sorted((repo / "defender-endpoint" / "api").glob("*.md"))
    routes: dict[str, dict] = {}
    entities: dict[str, list[str]] = {}
    for page in pages:
        text = page.read_text(encoding="utf-8", errors="replace")
        props = _PROPS.search(text)
        if props:
            names = []
            for line in props.group(1).splitlines()[2:]:
                cells = [c.strip() for c in line.strip("|").split("|")]
                if cells and cells[0] and not cells[0].startswith("-"):
                    names.append(cells[0].strip("`* "))
            if names:
                entities[page.stem] = names
        req = _REQUEST.search(text)
        # A few pages (the assessment exports) have no "## HTTP request"
        # section: their request lines sit in fences under numbered headings.
        verbs = (
            _VERB.findall(req.group(1))
            if req
            else [
                v
                for block in re.findall(r"```[A-Za-z]*\n(.*?)```", text, re.S)
                for v in _VERB.findall(block)
                if "/api/" in v[1]
            ]
        )
        if not verbs:
            continue
        # The page's response examples are its shape; the request examples
        # (bodies) are skipped by taking blocks after a "### Response" or
        # "## Response" heading only.
        paths: set[str] = set()
        for section in re.split(r"\n#{2,3} ", text):
            if section.lower().startswith("response"):
                for block in _json_blocks(section):
                    paths |= observed(block)
        # A page documents one operation; its examples belong to the first
        # request line (a second line is a variant such as a query option).
        for i, (verb, path) in enumerate(verbs):
            key = f"{verb.upper()} {_route(path)}"
            entry = routes.setdefault(key, {"page": page.name, "paths": set()})
            if i == 0:
                entry["paths"] |= paths
    reduced = {
        "routes": {
            k: {"page": v["page"], "paths": sorted(v["paths"])} for k, v in sorted(routes.items())
        },
        "entities": entities,
    }
    OUT.write_text(json.dumps(reduced, indent=1) + "\n")
    with_shape = sum(1 for v in routes.values() if v["paths"])
    print(
        f"pages: {len(pages)}  routes: {len(routes)} ({with_shape} with a response example)  entities: {len(entities)} → {OUT.relative_to(ROOT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/defender-docs")))
