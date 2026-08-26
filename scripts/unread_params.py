# ruff: noqa: ANN001, ANN201, ANN202, D103, S101, T201
# A release tool, not library code: every function is local to this file.
"""Find a route that declares a parameter and never looks at it.

Every other audit here asks the running mock a question. This one reads the
source, because the defect it looks for leaves no trace in a single answer:
a handler that takes `scope`, or `group_names`, or `filter` and never
mentions it again answers 200 with something plausible, and the parameter
the client sent simply never happened. `scripts/param_effect.py` catches the
ones a *value* makes visible — a limiter that does not limit — and cannot
catch the ones whose effect is invisible from outside: a `scope` the product
requires, a body a route was built to read.

Three kinds of declaration are not defects and are skipped:

* a `Depends(...)` parameter, whose presence *is* the effect — an auth
  dependency is never read by the handler that requires it;
* a parameter another layer answers for, listed in `_ELSEWHERE` with the
  layer that answers it: `output_mode` is Splunk middleware's, `api-version`
  is the ARM middleware's;
* a handler that reaches its arguments through `locals()`, which the
  SentinelOne routers do to collect their documented filters;
* a body the vendor's reference documents no member for, listed in
  `_NOTHING_TO_READ` — Cortex takes a `request_data` wrapper on every call
  and declares nothing inside it for those routes.

A *path* parameter is the strongest case of all, and is checked too: it
names the record the answer is meant to be about, so ignoring it answers
about a different one. `/accounts/{id}/policy` answered the same document
for every id, including ids the same install refuses on `/accounts/{id}`,
and `/endpoint/suggestions/{type}` answered the same list for a type Kibana
has no such thing as.

    backend/.venv/bin/python scripts/unread_params.py

Exit status 1 when anything is flagged.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "backend"

#: Parameters every handler takes and none reads by name.
_STRUCTURAL = frozenset({"self", "request", "response", "background_tasks"})

#: Parameter -> the layer that reads it instead of the handler. Each was
#: checked against the running mock before it was written down here.
_ELSEWHERE = {
    "output_mode": "the Splunk output-mode middleware renders it",
    "api_version": "the ARM middleware refuses a missing or unknown one",
    "pretty": "the Elasticsearch shaping middleware",
    "filter_path": "the Elasticsearch shaping middleware",
    "human": "not read by either, and neither product varies on it here",
    "v": "the `_cat` renderer takes it as a flag",
    "h": "the `_cat` renderer",
    "s": "the `_cat` renderer",
    "bytes": "the `_cat` renderer chooses the unit",
    "count": "the Splunk paging middleware",
    "offset": "the Splunk paging middleware",
    "f": "the Splunk field-filter middleware",
    "sort_key": "the Splunk sort middleware",
    "sort_dir": "the Splunk sort middleware",
    "sort_mode": "the Splunk sort middleware",
    "search": "the Splunk search middleware",
    "select": "`/me` refuses an app-only token before any projection",
}

#: Routes whose body the *reference* documents no member for. Cortex takes
#: a `request_data` wrapper on every call, and for these it declares nothing
#: inside it — `xdr_openapi_reduced.json` carries no `request_paths` for
#: them — so there is nothing for the handler to read. Checked one by one;
#: `rbac/get_user_group` and `quarantine/status` were on this list until the
#: reference showed they take `group_names` and `files`.
_NOTHING_TO_READ = {
    ("api/routers/xdr_distributions.py", "get_versions", "body"),
    ("api/routers/xdr_system.py", "get_tenant_info", "body"),
    ("api/routers/xdr_system.py", "get_users", "body"),
    ("api/routers/xdr_system.py", "get_roles", "body"),
    ("api/routers/xdr_system.py", "list_exclusions", "body"),
    ("api/routers/xdr_system.py", "get_device_control_violations", "body"),
    ("api/routers/xdr_xql.py", "get_quota", "body"),
}

#: Path parameters a route is right to ignore, with the reason. A path
#: parameter is otherwise the strongest case of all: it names the record the
#: answer is about, and ignoring it answers about a different one.
_NAMES_NOTHING = {
    # `/servicesNS/{owner}/{app}` is collapsed to `/services` by the
    # namespace middleware: this mock holds one namespace, and says so.
    ("api/routers/splunk/splunk_kvstore.py", "owner"),
    ("api/routers/splunk/splunk_catalogs.py", "owner"),
    ("api/routers/splunk/splunk_catalogs.py", "app"),
    # The whole ARM surface answers for one tenant addressed by any
    # subscription, resource group or workspace name — a mock cannot know a
    # customer's resource ids, and every Sentinel route agrees about it.
    ("api/routers/sentinel/sentinel_log_analytics.py", "workspace_id"),
}

#: How a parameter's default says where its value comes from.
_SOURCES = frozenset({"Query", "Form", "Body", "Header", "Cookie", "File"})


def is_route(node):
    """Whether this function is a route handler."""
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(target, ast.Attribute) and target.attr in (
            "get", "post", "put", "patch", "delete", "head", "options",
        ):
            return True
    return False


def names_read(node):
    """Every name the body of this function mentions."""
    return {
        sub.id for sub in ast.walk(ast.Module(body=node.body, type_ignores=[]))
        if isinstance(sub, ast.Name)
    }


def declared(node):
    """The handler's parameters, paired with the call that defaults them."""
    args = node.args.args + node.args.kwonlyargs
    defaults = (
        [None] * (len(node.args.args) - len(node.args.defaults))
        + list(node.args.defaults)
        + list(node.args.kw_defaults)
    )
    return list(zip(args, defaults, strict=False))


def path_parameters(node):
    """Every `{name}` the decorators of this handler put in the URL."""
    names = set()
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or not decorator.args:
            continue
        first = decorator.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            names |= {
                found.split(":")[0]
                for found in re.findall(r"\{([^}]+)\}", first.value)
            }
    return names


def unread(path, tree):
    """Every parameter this module's handlers declare and never read."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not is_route(node):
            continue
        body = ast.unparse(node.body) if node.body else ""
        if "locals()" in body:
            continue
        read = names_read(node)
        for argument, default in declared(node):
            name = argument.arg
            if name in _STRUCTURAL or name.startswith("_") or name in _ELSEWHERE:
                continue
            source = (
                default.func.id
                if isinstance(default, ast.Call) and isinstance(default.func, ast.Name)
                else ""
            )
            if source not in _SOURCES:
                continue
            if name in read or (path, node.name, name) in _NOTHING_TO_READ:
                continue
            found.append((path, node.name, name, source))

        for name in sorted(path_parameters(node)):
            if name.startswith("_") or name in read:
                continue
            if (path, name) in _NAMES_NOTHING:
                continue
            found.append((path, node.name, name, "path"))
    return found


def main():
    """Report every declared-and-never-read route parameter."""
    flags, handlers = [], 0
    for path in sorted(ROOT.rglob("*.py")):
        if "/tests/" in str(path):
            continue
        try:
            tree = ast.parse(path.read_text())
        except SyntaxError:
            continue
        handlers += sum(
            1 for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and is_route(node)
        )
        flags += unread(str(path.relative_to(ROOT)), tree)

    print(f"=== UNREAD PARAMETERS === {handlers} route handler(s) read")
    for path, handler, name, source in flags:
        print(f"  {path:48} {handler:34} {name} ({source})")
    print(f"\n  {len(flags)} parameter(s) declared and never read")
    return 1 if flags else 0


if __name__ == "__main__":
    sys.exit(main())
