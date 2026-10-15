"""The search macros mockdr's SPL expands, and ``admin/macros`` lists.

A macro is written in backticks and expanded before the search is parsed;
one that takes arguments is named with its arity, ``name(1)``, and its
definition names each argument as ``$arg$`` (Knowledge Manager Manual,
"Use search macros in searches").

* ``notable`` is Enterprise Security's: the notable index.
* ``drop_dm_object_name(1)`` is the CIM add-on's, and nearly every ES
  correlation search ends its ``tstats`` with it: it strips the dataset
  prefix, so ``Processes.dest`` reads as ``dest``.

Expansion is one pass over the search text. A definition is not expanded
again, so no macro can expand into itself without end.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Macro:
    """A macro's definition, its argument names, and the app it lives in."""

    definition: str
    args: tuple[str, ...] = ()
    app: str = "search"


MACROS: dict[str, Macro] = {
    "notable": Macro("search index=notable"),
    "drop_dm_object_name(1)": Macro(
        "rename $object$.* AS *", args=("object",), app="Splunk_SA_CIM",
    ),
}

#: `` `name` `` or `` `name(arg, …)` ``; neither part can contain a backtick.
_MACRO_RE = re.compile(r"`([A-Za-z_]\w*)(?:\(([^`()]*)\))?`")


def expand_macros(text: str) -> str:
    """The search with every macro mockdr knows expanded, once.

    ``notable`` is left for the parser, which marks the search as a notable
    one; a macro mockdr does not know is left as it was written.
    """
    def expand(match: re.Match[str]) -> str:
        name, raw = match.group(1), match.group(2)
        args = [] if raw is None else [a.strip() for a in raw.split(",")]
        macro = MACROS.get(f"{name}({len(args)})" if raw is not None else name)
        if macro is None or name == "notable":
            return match.group(0)
        definition = macro.definition
        for arg_name, value in zip(macro.args, args, strict=False):
            definition = definition.replace(f"${arg_name}$", value)
        return definition

    return _MACRO_RE.sub(expand, text)
