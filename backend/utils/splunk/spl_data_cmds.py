"""The SPL commands that read beyond their input rows.

``inputlookup`` and ``lookup`` read lookup tables; ``tstats`` reads the index
— or a CIM data model over it — directly; ``chart`` pivots; ``append`` and
``join`` run a subsearch. Splunk Enterprise Security's correlation searches
are built from these, and mockdr refused every one of them as an unknown
command.

What they read comes through :class:`~utils.splunk.spl_sources.SearchSources`,
so this module holds no repository. Every command that can produce rows in
bulk is held to the limits.conf ceiling a real search head applies (see
:data:`MAX_RESULT_ROWS`).

Semantics follow the Search Reference (help.splunk.com, SPL search
reference: inputlookup, lookup, tstats, chart, append, join) and
transforms.conf.
"""
from __future__ import annotations

import itertools
import math
import re
from collections import OrderedDict
from collections.abc import Callable
from typing import Any

from utils.numbers import as_float
from utils.splunk.spl_datamodels import DATA_MODELS, INHERITED_FIELDS, Dataset
from utils.splunk.spl_exec import (
    _ABSENT,
    _COUNT_RE,
    _DURATION_UNITS,
    MAX_EXPANDED_ROWS,
    OptionError,
    _aggregate,
    _boolean_option,
    _fields,
    _invalid_argument,
    _known_aggregation,
    _option_error,
    _parse_aggregations,
    _shrink,
    _sortable,
)
from utils.splunk.spl_expr import evaluate, parse_search
from utils.splunk.spl_functions import one_or_many, values_of
from utils.splunk.spl_parser import (
    SPLCommand,
    SPLQuery,
    _parse_search_clause,
    current_time,
    resolve_relative_time,
)
from utils.splunk.spl_sources import (
    SOURCES,
    SUBSEARCH_COUNT,
    SUBSEARCH_DEPTH,
    TIME_WINDOW,
    EventSelector,
    LookupTable,
    SearchSources,
)

Rows = list[dict[str, Any]]

#: limits.conf ``[searchresults] maxresultrows``: the most rows a search
#: hands back, 50,000 by default. The KV Store's own cap on one query,
#: ``[kvstore] max_rows_per_query``, is the same number, so ``inputlookup``
#: over a collection stops there in both senses.
MAX_RESULT_ROWS = 50_000

#: ``append``'s ``maxout``: the most subsearch rows it takes, 50,000 by
#: default (append command reference).
MAX_APPEND_ROWS = 50_000

#: How deep subsearches may nest here. splunkd bounds a subsearch by time
#: (``maxtime``); a synchronous mock bounds the nesting instead, so a search
#: of brackets inside brackets cannot recurse without end.
MAX_SUBSEARCH_DEPTH = 4

#: How many subsearches one search may run, however they are arranged. Depth
#: alone does not bound the work: a flat chain of a thousand `append`s nests
#: nothing and would generate a thousand result sets.
MAX_SUBSEARCHES = 16

#: The most rows ``append`` leaves behind, its own rows and the subsearch's
#: together — the same ceiling ``mvexpand`` stops at, so a chain of appends
#: cannot grow the result set without end.
MAX_APPENDED_TOTAL = MAX_EXPANDED_ROWS

#: How many combinations of a multivalue event's values one lookup tries.
_MAX_LOOKUP_KEYS = 100


def _sources() -> SearchSources:
    """The search's data, or the failure a search without any meets."""
    sources = SOURCES.get()
    if sources is None:
        msg = "This search has no data to read."
        raise ValueError(msg)
    return sources


#: An argument token: a quoted string, or a run of anything but space and comma.
_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"|[^\s,]+')


def _tokens(arg: str) -> list[str]:
    """Split on whitespace and commas outside quotes, unquoting each token."""
    out = []
    for match in _TOKEN_RE.finditer(arg):
        token = match.group(0)
        if len(token) > 1 and token.startswith('"') and token.endswith('"'):
            token = token[1:-1].replace('\\"', '"')
        out.append(token)
    return out


# ---------------------------------------------------------------------------
# inputlookup
# ---------------------------------------------------------------------------

_INPUTLOOKUP_OPTIONS = frozenset({"append", "strict", "start", "max"})

#: ``where`` as a whole word, outside quotes, after the table name.
_WHERE_RE = re.compile(r"\s(?i:where)\s")


def _missing_table(name: str) -> ValueError:
    """What splunkd says when ``inputlookup`` names no table it has.

    A name ending in ``.csv`` is a file that is not there; anything else
    needed a lookup definition that does not exist.
    """
    if name.lower().endswith(".csv"):
        return ValueError(f"The lookup table '{name}' does not exist or is not available.")
    return ValueError(
        f"The lookup table '{name}' requires a .csv or KV store lookup definition.",
    )


def inputlookup_appends(arg: str) -> bool:
    """Whether this ``inputlookup`` adds to the rows instead of generating them."""
    head = _WHERE_RE.split(f" {arg} ", maxsplit=1)[0]
    match = re.search(r"(?i)\bappend\s*=\s*(\S+)", head)
    if match is None:
        return False
    return match.group(1).strip('"').lower() in ("t", "true", "1", "yes")


def cmd_inputlookup(rows: Rows, command: SPLCommand) -> Rows:
    """Read a lookup table as search results.

    ``inputlookup [append=<bool>] [strict=<bool>] [start=<int>] [max=<int>]
    <name> [WHERE <search>]``. ``start`` skips rows from the top, ``max``
    caps how many are read, and the ``WHERE`` clause is a search-command
    expression — field=value with wildcards, ``OR``, ``NOT``, comparisons —
    applied to the table's rows before either. With ``append=true`` the
    table's rows follow the rows already there; otherwise the command must
    begin the search.
    """
    head, where_text = command.arg, ""
    match = _WHERE_RE.search(f" {command.arg} ")
    if match:
        cut = max(match.start() - 1, 0)
        head, where_text = command.arg[:cut], command.arg[match.end() - 1:]

    options: dict[str, str] = {}
    name = ""
    for token in _tokens(head):
        option = re.fullmatch(r"(\w+)=(.*)", token)
        if option and not name and option.group(1).lower() in _INPUTLOOKUP_OPTIONS:
            options[option.group(1).lower()] = option.group(2)
        elif name or option:
            msg = f"Invalid argument: '{token}'"
            raise ValueError(msg)
        else:
            name = token
    if not name:
        msg = "Must specify a lookup table name."
        raise ValueError(msg)

    append = _boolean_option("append", options["append"]) if "append" in options else False
    if "strict" in options:
        _boolean_option("strict", options["strict"])
    start = _count_option("start", options.get("start", "0"))
    limit = _count_option("max", options["max"]) if "max" in options else MAX_RESULT_ROWS

    table = _sources().lookup(name)
    if table is None:
        raise _missing_table(name)

    found = table.rows
    if where_text.strip():
        node = parse_search(where_text)
        found = [r for r in found if evaluate(node, r, mode="search")]
    found = found[start:start + min(limit, MAX_RESULT_ROWS)]
    produced = [_table_row(table, r) for r in found]
    return [*rows, *produced] if append else produced


def _count_option(name: str, raw: str) -> int:
    if not _COUNT_RE.fullmatch(raw):
        raise _option_error(name, "non-negative integer", raw)
    return int(raw)


def _table_row(table: LookupTable, row: dict[str, Any]) -> dict[str, Any]:
    """A table row as a result: its fields in the table's order."""
    return {f: row[f] for f in table.fields if row.get(f) not in (None, "")}


# ---------------------------------------------------------------------------
# lookup
# ---------------------------------------------------------------------------

_LOOKUP_OPTIONS = frozenset({"local", "update", "event_time_field"})


def _construct_failure(arg: str) -> ValueError:
    """The refusal of a lookup splunkd cannot build, quoting its arguments."""
    return ValueError(
        f"Could not construct lookup '{', '.join(_tokens(arg))}'. "
        "See search.log for more details.",
    )


def _pairs(tokens: list[str]) -> list[tuple[str, str]]:
    """``a AS b c`` → ``[(a, b), (c, c)]``."""
    pairs: list[tuple[str, str]] = []
    position = 0
    while position < len(tokens):
        source = tokens[position]
        if position + 1 < len(tokens) and tokens[position + 1].lower() == "as":
            if position + 2 >= len(tokens):
                msg = f"Invalid argument: '{tokens[position + 1]}'"
                raise ValueError(msg)
            pairs.append((source, tokens[position + 2]))
            position += 3
            continue
        pairs.append((source, source))
        position += 1
    return pairs


def cmd_lookup(rows: Rows, command: SPLCommand) -> Rows:
    """Enrich each row from a lookup table.

    ``lookup <name> (<lookup-field> [AS <event-field>])... [OUTPUT |
    OUTPUTNEW (<lookup-field> [AS <event-field>])...]``. A row matches a
    table row when every match field agrees — case-sensitively unless the
    definition says otherwise — and each output field takes the values of
    up to ``max_matches`` matching rows, as a multivalue when there are
    several. Without an output clause every table field that is not a match
    field is written. ``OUTPUT`` overwrites, so a row that matches nothing
    loses the output fields it had; ``OUTPUTNEW`` writes only fields the row
    does not have, and skips a row that has all of them.
    """
    tokens = _tokens(command.arg)
    options: dict[str, str] = {}
    while tokens and re.fullmatch(r"(\w+)=(.*)", tokens[0]) and (
        tokens[0].split("=", 1)[0].lower() in _LOOKUP_OPTIONS
    ):
        key, _, value = tokens.pop(0).partition("=")
        options[key.lower()] = value
    for flag in ("local", "update"):
        if flag in options:
            _boolean_option(flag, options[flag])
    if not tokens:
        msg = "Must specify a lookup table name."
        raise ValueError(msg)
    name = tokens.pop(0)

    mode = ""
    split = next(
        (i for i, t in enumerate(tokens) if t.upper() in ("OUTPUT", "OUTPUTNEW")), None,
    )
    output_tokens: list[str] = []
    if split is not None:
        mode = tokens[split].upper()
        output_tokens = tokens[split + 1:]
        tokens = tokens[:split]
    inputs = _pairs(tokens)

    table = _sources().lookup(name)
    if table is None:
        raise _construct_failure(command.arg)
    if not inputs:
        msg = "Must specify one or more lookup fields."
        raise ValueError(msg)
    if any(source not in table.fields for source, _ in inputs):
        msg = "Could not find all of the specified lookup fields in the lookup table."
        raise ValueError(msg)
    if mode and not output_tokens:
        msg = f"Must specify one or more destination fields after {mode}."
        raise ValueError(msg)
    match_fields = {source for source, _ in inputs}
    outputs = _pairs(output_tokens) if mode else [
        (f, f) for f in table.fields if f not in match_fields
    ]
    if any(source not in table.fields for source, _ in outputs):
        msg = "Could not find all of the specified destination fields in the lookup table."
        raise ValueError(msg)

    index = _match_index(table, [source for source, _ in inputs])
    out: Rows = []
    for row in rows:
        enriched = dict(row)
        targets = [dest for _, dest in outputs]
        if mode == "OUTPUTNEW" and all(enriched.get(t) not in (None, "") for t in targets):
            out.append(enriched)
            continue
        matches = _matches(table, index, [row.get(dest) for _, dest in inputs])
        for source, dest in outputs:
            values = [m[source] for m in matches if m.get(source) not in (None, "")]
            if not values and table.min_matches > len(matches) and table.default_match:
                values = [table.default_match]
            if mode == "OUTPUTNEW" and enriched.get(dest) not in (None, ""):
                continue
            if values:
                enriched[dest] = one_or_many(values)
            else:
                enriched.pop(dest, None)
        out.append(enriched)
    return out


def _normal(table: LookupTable, value: Any) -> str:
    text = str(value)
    return text if table.case_sensitive_match else text.lower()


def _match_index(table: LookupTable, fields: list[str]) -> dict[tuple[str, ...], Rows]:
    """The table's rows keyed by their match-field values, in table order."""
    index: dict[tuple[str, ...], Rows] = {}
    for row in table.rows:
        if any(row.get(f) in (None, "") for f in fields):
            continue
        index.setdefault(
            tuple(_normal(table, row[f]) for f in fields), [],
        ).append(row)
    return index


def _matches(
    table: LookupTable, index: dict[tuple[str, ...], Rows], event_values: list[Any],
) -> Rows:
    """The table rows an event's match values select, up to ``max_matches``.

    A multivalue event field is looked up value by value.
    """
    choices = []
    for value in event_values:
        if value in (None, ""):
            return []
        choices.append([v for v in values_of(value) if v not in (None, "")])
    found: Rows = []
    for combination in itertools.islice(itertools.product(*choices), _MAX_LOOKUP_KEYS):
        for row in index.get(tuple(_normal(table, v) for v in combination), []):
            if len(found) >= table.max_matches:
                return found
            found.append(row)
    return found


# ---------------------------------------------------------------------------
# tstats
# ---------------------------------------------------------------------------

_TSTATS_OPTIONS = frozenset({
    "prestats", "local", "append", "summariesonly", "include_reduced_buckets",
    "allow_old_summaries", "chunk_size", "fillnull_value",
})

#: The statistics tstats offers. ``list``, ``first`` and ``last`` are
#: stats functions it does not have (tstats command reference).
_TSTATS_REFUSED = frozenset({"list", "first", "last"})
_TSTATS_EXTRA = frozenset({"estdc", "earliest_time", "latest_time"})

#: The fields an index holds for every event without a data model: what
#: ``tstats`` can see when it reads the tsidx files directly. Fields a
#: search extracts at search time are not among them.
INDEXED_FIELDS = ("_time", "index", "sourcetype", "source", "host")


def _keyword_spans(text: str, keywords: tuple[str, ...]) -> list[tuple[str, int, int]]:
    """Each keyword's position, as a whole word outside quotes and brackets."""
    spans: list[tuple[str, int, int]] = []
    depth = 0
    in_quotes = False
    position = 0
    while position < len(text):
        char = text[position]
        if char == '"':
            in_quotes = not in_quotes
        elif not in_quotes and char in "([":
            depth += 1
        elif not in_quotes and char in ")]":
            depth = max(depth - 1, 0)
        elif not in_quotes and depth == 0 and (position == 0 or text[position - 1].isspace()):
            for word in keywords:
                end = position + len(word)
                if text[position:end].lower() == word and (
                    end == len(text) or text[end].isspace()
                ):
                    spans.append((word, position, end))
                    position = end - 1
                    break
        position += 1
    return spans


def _clauses(text: str) -> dict[str, str]:
    """``<head> FROM … WHERE … BY …`` → its clauses by keyword."""
    spans = _keyword_spans(text, ("from", "where", "by"))
    clauses: dict[str, str] = {}
    head_end = spans[0][1] if spans else len(text)
    clauses["head"] = text[:head_end]
    for position, (word, _start, end) in enumerate(spans):
        stop = spans[position + 1][1] if position + 1 < len(spans) else len(text)
        if word in clauses:
            msg = f"Invalid argument: '{word}'"
            raise ValueError(msg)
        clauses[word] = text[end:stop]
    return clauses


def tstats_appends(arg: str) -> bool:
    """Whether this ``tstats`` runs on top of existing results (prestats append)."""
    head = _clauses(arg)["head"]
    return bool(re.search(r"(?i)\bappend\s*=\s*(t|true|1|yes)\b", head)) and bool(
        re.search(r"(?i)\bprestats\s*=\s*(t|true|1|yes)\b", head),
    )


def _split_options(head: str) -> tuple[dict[str, str], str]:
    options: dict[str, str] = {}

    def take(match: re.Match[str]) -> str:
        options[match.group(1).lower()] = match.group(2).strip('"')
        return " "

    pattern = r"(?i)\b(" + "|".join(sorted(_TSTATS_OPTIONS)) + r")\s*=\s*(\"[^\"]*\"|\S+)"
    rest = re.sub(pattern, take, head)
    return options, rest


def _span(by_text: str) -> tuple[float, str]:
    """A ``span=`` in the by clause, in seconds, and the clause without it."""
    match = re.search(r"(?i)\bspan\s*=\s*(\S+)", by_text)
    if not match:
        return 0.0, by_text
    raw = match.group(1)
    parsed = re.fullmatch(r"(?i)(\d+)\s*(s|m|h|d|w)?", raw)
    if not parsed or int(parsed.group(1)) == 0:
        raise _option_error("span", "time span", raw)
    seconds = float(int(parsed.group(1)) * _DURATION_UNITS[(parsed.group(2) or "s").lower()])
    return seconds, by_text[: match.start()] + " " + by_text[match.end():]


def _dataset_of(source: str, where: str) -> tuple[list[Dataset], str]:
    """The datasets ``datamodel=`` names, and the where clause left over.

    ``datamodel=Endpoint.Processes`` names one root dataset; a bare
    ``datamodel=Endpoint`` reads every root dataset of the model, or the one
    a ``nodename=`` term in the where clause picks.
    """
    match = re.fullmatch(r'(?i)\s*datamodel\s*[=:]\s*"?([^"\s]+)"?\s*', source)
    if not match:
        msg = f"Invalid argument: '{source.strip()}'"
        raise ValueError(msg)
    model_name, _, dataset_name = match.group(1).partition(".")
    node = re.search(r'(?i)\bnodename\s*=\s*"?([^"\s]+)"?', where)
    if node:
        where = where[: node.start()] + " " + where[node.end():]
        dataset_name = dataset_name or node.group(1).split(".")[-1]
    model = DATA_MODELS.get(model_name)
    if model is None:
        msg = f"Data model '{model_name}' was not found."
        raise OptionError(msg, subject="DataModelEvaluator")
    if not dataset_name:
        return list(model.datasets), where
    dataset = model.dataset(dataset_name.split(".")[0])
    if dataset is None:
        msg = f"Data model '{model_name}' does not contain object '{dataset_name}'."
        raise OptionError(msg, subject="DataModelEvaluator")
    return [dataset], where


def _window(selector: SPLQuery) -> tuple[float, float]:
    """The time window: the dispatch's, else the where clause's own terms."""
    now = current_time()
    earliest, latest = TIME_WINDOW.get()
    for term in ("earliest", "latest"):
        value = getattr(selector, f"{term}_time")
        if not value:
            continue
        resolved = resolve_relative_time(value, now)
        if not resolved:
            msg = f"Invalid value \"{value}\" for time term '{term}'"
            raise OptionError(msg, subject="")
        if term == "earliest" and not earliest:
            earliest = resolved
        elif term == "latest" and not latest:
            latest = resolved
    return earliest, latest


def cmd_tstats(rows: Rows, command: SPLCommand) -> Rows:
    """Statistics over indexed fields, or over a CIM data model.

    ``tstats [prestats=<bool>] [summariesonly=<bool>] [fillnull_value=<v>]
    … <stats-func>... [FROM datamodel=<model>[.<dataset>]] [WHERE <search>]
    [BY <field>... [span=<span>]]``.

    Without ``FROM`` it reads the index's own fields only — ``_time``,
    ``index``, ``sourcetype``, ``source``, ``host`` — so `tstats count where
    index=main by sourcetype` works and a field extracted at search time
    groups nothing. With a data model it reads the dataset's CIM fields,
    written with the dataset's prefix (``Processes.process_name``), beside
    the unprefixed fields every event inherits. Every data model here is
    accelerated with a complete summary, so ``summariesonly`` changes
    nothing. A row missing a by-field belongs to no group unless
    ``fillnull_value`` names what to group it under. ``prestats=true`` hands
    the matching rows on for a following ``stats``, ``chart`` or
    ``timechart`` to finish — not splunkd's internal prestats encoding, but
    the same answer once that command has run.
    """
    clauses = _clauses(command.arg)
    options, agg_text = _split_options(clauses["head"])
    for flag in ("prestats", "local", "append", "summariesonly",
                 "include_reduced_buckets", "allow_old_summaries"):
        if flag in options:
            _boolean_option(flag, options[flag])
    prestats = _boolean_option("prestats", options.get("prestats", "f"))
    fill = options.get("fillnull_value")

    aggs = _parse_aggregations(agg_text)
    remainder = agg_text
    for match in re.finditer(r"\w+\s*\([^)]*\)(?:\s+as\s+[^\s,]+)?|\bcount\b(?:\s+as\s+[^\s,]+)?",
                             agg_text, re.IGNORECASE):
        remainder = remainder.replace(match.group(0), " ", 1)
    leftover = [t for t in re.split(r"[,\s]+", remainder) if t]
    if leftover:
        raise _invalid_argument(leftover[0])
    for func, _field, _alias in aggs:
        if func in _TSTATS_REFUSED or not (_known_aggregation(func) or func in _TSTATS_EXTRA):
            raise _invalid_argument(func)
    if not aggs:
        msg = "This command requires at least one aggregation."
        raise ValueError(msg)

    where = clauses.get("where", "")
    datasets: list[Dataset] | None = None
    if "from" in clauses:
        datasets, where = _dataset_of(clauses["from"], where)
    span, by_text = _span(clauses.get("by", ""))
    by_fields = _fields(by_text)
    if "by" in clauses and not by_fields:
        msg = "Must specify at least one field after BY."
        raise ValueError(msg)

    selector = SPLQuery()
    _parse_search_clause(where, selector)
    if selector.errors:
        raise ValueError(selector.errors[0])
    earliest, latest = _window(selector)
    events = _sources().events(EventSelector(
        index=selector.index, sourcetype=selector.sourcetype,
        source=selector.source, host=selector.host,
        earliest=earliest, latest=latest,
    ))
    if datasets is None:
        candidates = [{k: e[k] for k in INDEXED_FIELDS if k in e} for e in events]
    else:
        candidates = [row for dataset in datasets for row in dataset.rows(events)]
    if selector.search_expr is not None:
        candidates = [r for r in candidates if evaluate(selector.search_expr, r, mode="search")]

    if span and "_time" in by_fields:
        for row in candidates:
            stamp = as_float(row.get("_time"))
            if stamp is not None:
                row["_time"] = _shrink(math.floor(stamp / span) * span)
    if fill is not None:
        for row in candidates:
            for name in by_fields:
                if row.get(name) in (None, ""):
                    row[name] = fill

    if prestats:
        wanted = set(by_fields) | {f for _, f, _ in aggs if f} | {"_time"}
        handed = [{k: v for k, v in r.items() if k in wanted} for r in candidates]
        return [*rows, *handed[:MAX_RESULT_ROWS]]
    return _tstats_groups(aggs, by_fields, candidates)


def _tstats_aggregate(func: str, field: str, members: Rows) -> Any:
    if func in ("earliest_time", "latest_time"):
        stamps = [as_float(r.get("_time")) for r in members if r.get(field) is not None]
        known = [s for s in stamps if s is not None]
        if not known:
            return _ABSENT
        return _shrink(min(known) if func == "earliest_time" else max(known))
    return _aggregate("dc" if func == "estdc" else func, field, members)


def _tstats_groups(aggs: list[tuple[str, str, str]], by_fields: list[str], rows: Rows) -> Rows:
    def computed(members: Rows) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for func, field, alias in aggs:
            value = _tstats_aggregate(func, field, members)
            if value is not _ABSENT:
                record[alias] = value
        return record

    if not by_fields:
        whole = computed(rows)
        return [whole] if whole else []
    groups: OrderedDict[tuple, Rows] = OrderedDict()
    for row in rows:
        if any(row.get(f) in (None, "") for f in by_fields):
            continue
        key = tuple(str(row[f]) for f in by_fields)
        groups.setdefault(key, []).append(row)
    out: Rows = []
    for key in sorted(groups, key=lambda k: tuple(_sortable(v) for v in k))[:MAX_RESULT_ROWS]:
        record: dict[str, Any] = {
            # A bucketed `_time` stays the number it was; every other
            # by-value reads as text, as `stats` writes it.
            name: groups[key][0][name] if name == "_time" else value
            for name, value in zip(by_fields, key, strict=False)
        }
        record.update(computed(groups[key]))
        out.append(record)
    return out


# ---------------------------------------------------------------------------
# chart
# ---------------------------------------------------------------------------

_CHART_OPTIONS = frozenset({
    "limit", "useother", "otherstr", "usenull", "nullstr", "cont", "agg", "sep", "format",
})

#: Statistics whose value over no rows is a number rather than nothing.
_COUNTING = frozenset({"count", "c", "dc", "distinct_count", "estdc"})


def cmd_chart(rows: Rows, command: SPLCommand) -> Rows:
    """A statistics table pivoted on two fields.

    ``chart <stats-func>... [OVER <row-field> [BY <column-field>]]``, or
    ``BY <row-field>[, <column-field>]``. One output row per value of the
    row field, in order; one column per value of the column field, named by
    the value (``"<stat>: <value>"`` when there are several statistics).
    Past ``limit`` columns (10 by default, 0 for no limit) the smallest are
    folded into ``OTHER``; a row without the column field counts under
    ``NULL``. An empty cell of a counting statistic is 0, of any other
    absent.
    """
    options: dict[str, str] = {}

    def take(match: re.Match[str]) -> str:
        options[match.group(1).lower()] = match.group(2).strip('"')
        return " "

    pattern = r"(?i)\b(" + "|".join(sorted(_CHART_OPTIONS)) + r")\s*=\s*(\"[^\"]*\"|\S+)"
    text = re.sub(pattern, take, command.arg)
    spans = _keyword_spans(text, ("over", "by"))
    agg_text = text[: spans[0][1]] if spans else text
    parts = {word: text[end:(spans[i + 1][1] if i + 1 < len(spans) else len(text))]
             for i, (word, _s, end) in enumerate(spans)}
    if "over" in parts:
        row_field = (_fields(parts["over"]) or [""])[0]
        column_fields = _fields(parts.get("by", ""))
    else:
        named = _fields(parts.get("by", ""))
        row_field = named[0] if named else ""
        column_fields = named[1:]
    if len(column_fields) > 1:
        raise _invalid_argument(column_fields[1])
    column_field = column_fields[0] if column_fields else ""

    aggs = _parse_aggregations(agg_text)
    remainder = agg_text
    for match in re.finditer(r"\w+\s*\([^)]*\)(?:\s+as\s+[^\s,]+)?|\bcount\b(?:\s+as\s+[^\s,]+)?",
                             agg_text, re.IGNORECASE):
        remainder = remainder.replace(match.group(0), " ", 1)
    leftover = [t for t in re.split(r"[,\s]+", remainder) if t]
    if leftover:
        raise _invalid_argument(leftover[0])
    for func, _f, _a in aggs:
        if not _known_aggregation(func):
            raise _invalid_argument(func)
    if not aggs:
        msg = "You must specify data field(s) to chart."
        raise ValueError(msg)

    limit_raw = options.get("limit", "10")
    limit_match = re.fullmatch(r"(?i)(?:top|bottom)?(\d+)", limit_raw)
    if not limit_match:
        raise _option_error("limit", "non-negative integer", limit_raw)
    limit = int(limit_match.group(1))
    use_other = _boolean_option("useother", options.get("useother", "t"))
    use_null = _boolean_option("usenull", options.get("usenull", "t"))
    other = options.get("otherstr", "OTHER")
    null = options.get("nullstr", "NULL")

    groups: OrderedDict[str, Rows] = OrderedDict()
    for row in rows:
        if row_field:
            if row.get(row_field) in (None, ""):
                continue
            groups.setdefault(str(row[row_field]), []).append(row)
        else:
            groups.setdefault("", []).append(row)
    order = sorted(groups, key=_sortable)

    def cells(members: Rows) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for func, field, alias in aggs:
            value = _aggregate(func, field, members)
            if value is not _ABSENT:
                record[alias] = value
        return record

    if not column_field:
        out = []
        for key in order[:MAX_RESULT_ROWS]:
            record: dict[str, Any] = {row_field: groups[key][0][row_field]} if row_field else {}
            record.update(cells(groups[key]))
            out.append(record)
        return out

    def column_of(row: dict[str, Any]) -> str | None:
        value = row.get(column_field)
        if value in (None, ""):
            return null if use_null else None
        return str(value)

    totals: dict[str, float] = {}
    for row in rows:
        column = column_of(row)
        if column is not None:
            totals[column] = totals.get(column, 0.0) + 1.0
    columns = sorted(totals, key=_sortable)
    folded: set[str] = set()
    if limit and len(columns) > limit:
        kept = set(sorted(columns, key=lambda c: (-totals[c], _sortable(c)))[:limit])
        folded = {c for c in columns if c not in kept}
        columns = [c for c in columns if c in kept] + ([other] if use_other else [])

    def names(column: str) -> list[tuple[str, str, str]]:
        if len(aggs) == 1:
            return [(aggs[0][0], aggs[0][1], column)]
        return [(f, fld, f"{alias}: {column}") for f, fld, alias in aggs]

    out = []
    for key in order[:MAX_RESULT_ROWS]:
        members = groups[key]
        record = {row_field: members[0][row_field]}
        for column in columns:
            wanted = folded if column == other and folded else {column}
            in_cell = [r for r in members if column_of(r) in wanted]
            for func, field, name in names(column):
                value = _aggregate(func, field, in_cell) if in_cell else (
                    0 if func.lower() in _COUNTING else _ABSENT
                )
                if value is not _ABSENT:
                    record[name] = value
        out.append(record)
    return out


# ---------------------------------------------------------------------------
# append
# ---------------------------------------------------------------------------

_APPEND_OPTIONS = frozenset({"extendtimerange", "maxtime", "maxout"})


class SubsearchFailedError(ValueError):
    """A subsearch could not run; its own message is the search's."""


def subsearch_text(arg: str) -> tuple[str, str]:
    """Split ``[options] [ <spl> ]`` into the options and the bracketed SPL."""
    start = arg.find("[")
    if start < 0 or not arg.rstrip().endswith("]"):
        msg = "Missing subsearch."
        raise ValueError(msg)
    return arg[:start], arg[start + 1: arg.rstrip().rfind("]")]


def run_subsearch(spl: str) -> Rows:
    """Run a subsearch, refusing one nested deeper than mockdr follows."""
    depth = SUBSEARCH_DEPTH.get()
    if depth >= MAX_SUBSEARCH_DEPTH:
        msg = f"Subsearches may be nested at most {MAX_SUBSEARCH_DEPTH} deep."
        raise ValueError(msg)
    counter = SUBSEARCH_COUNT.get()
    if counter is not None:
        counter[0] += 1
        if counter[0] > MAX_SUBSEARCHES:
            msg = f"A search may run at most {MAX_SUBSEARCHES} subsearches."
            raise ValueError(msg)
    token = SUBSEARCH_DEPTH.set(depth + 1)
    try:
        found, messages = _sources().subsearch(spl.strip())
    finally:
        SUBSEARCH_DEPTH.reset(token)
    fatal = next((m for m in messages if m.get("type") == "FATAL"), None)
    if fatal is not None:
        raise SubsearchFailedError(fatal["text"])
    return found


def cmd_append(rows: Rows, command: SPLCommand) -> Rows:
    """Run a subsearch and add its results after the current ones.

    ``append [extendtimerange=<bool>] [maxtime=<int>] [maxout=<int>]
    [<subsearch>]``. The subsearch runs over the search's own time range and
    contributes at most ``maxout`` rows (50,000 by default and at most).
    """
    head, spl = subsearch_text(command.arg)
    options: dict[str, str] = {}
    for token in _tokens(head):
        option = re.fullmatch(r"(\w+)=(.*)", token)
        if not option or option.group(1).lower() not in _APPEND_OPTIONS:
            msg = f"Invalid argument: '{token}'"
            raise ValueError(msg)
        options[option.group(1).lower()] = option.group(2)
    if "extendtimerange" in options:
        _boolean_option("extendtimerange", options["extendtimerange"])
    maxout = _count_option("maxout", options.get("maxout", str(MAX_APPEND_ROWS)))
    if "maxtime" in options:
        _count_option("maxtime", options["maxtime"])
    found = run_subsearch(spl)
    combined = [*rows, *found[: min(maxout, MAX_APPEND_ROWS)]]
    return combined[:MAX_APPENDED_TOTAL]


# ---------------------------------------------------------------------------
# join
# ---------------------------------------------------------------------------

_JOIN_OPTIONS = frozenset({"type", "usetime", "earlier", "overwrite", "max"})

#: limits.conf ``[join] subsearch_maxout``: the most subsearch rows a join
#: reads, 50,000 by default.
MAX_JOIN_ROWS = 50_000


def cmd_join(rows: Rows, command: SPLCommand) -> Rows:
    """Join each row to the subsearch's rows that agree on the join fields.

    ``join [type=inner|outer|left] [usetime=<bool>] [earlier=<bool>]
    [overwrite=<bool>] [max=<int>] [<field>...] [<subsearch>]``. Without
    fields, every field the two result sets share is a join field. A row
    takes up to ``max`` matching subsearch rows (1 by default, 0 for all),
    one output row each; ``inner`` drops a row that matches none, ``outer``
    and ``left`` keep it as it was. The subsearch's fields win over the
    row's unless ``overwrite=false``. ``usetime=true`` only joins subsearch
    rows from before the row (``earlier=true``, the default) or after it.
    """
    head, spl = subsearch_text(command.arg)
    options: dict[str, str] = {}
    fields: list[str] = []
    for token in _tokens(head):
        option = re.fullmatch(r"(\w+)=(.*)", token)
        if option and option.group(1).lower() in _JOIN_OPTIONS:
            options[option.group(1).lower()] = option.group(2)
        elif option:
            msg = f"Invalid argument: '{token}'"
            raise ValueError(msg)
        else:
            fields.append(token)
    kind = options.get("type", "inner").lower()
    if kind not in ("inner", "outer", "left"):
        raise _option_error("type", "inner, outer, or left", options["type"])
    overwrite = _boolean_option("overwrite", options.get("overwrite", "t"))
    usetime = _boolean_option("usetime", options.get("usetime", "f"))
    earlier = _boolean_option("earlier", options.get("earlier", "t"))
    limit = _count_option("max", options.get("max", "1"))

    found = run_subsearch(spl)[:MAX_JOIN_ROWS]
    if not fields:
        ours = {k for row in rows for k in row}
        theirs = {k for row in found for k in row}
        fields = sorted(ours & theirs)
    index: dict[tuple[str, ...], Rows] = {}
    for row in found:
        if any(row.get(f) in (None, "") for f in fields):
            continue
        index.setdefault(tuple(str(row[f]) for f in fields), []).append(row)

    out: Rows = []
    for row in rows:
        key = None if any(row.get(f) in (None, "") for f in fields) else tuple(
            str(row[f]) for f in fields
        )
        matches = index.get(key, []) if key is not None else []
        if usetime:
            stamp = as_float(row.get("_time")) or 0.0
            matches = [
                m for m in matches
                if ((as_float(m.get("_time")) or 0.0) <= stamp) == earlier
            ]
        if limit:
            matches = matches[:limit]
        if not matches:
            if kind != "inner":
                out.append(dict(row))
            continue
        for match in matches:
            out.append({**row, **match} if overwrite else {**match, **row})
            if len(out) >= MAX_APPENDED_TOTAL:
                return out
    return out


HANDLERS: dict[str, Callable[[Rows, SPLCommand], Rows]] = {
    "append": cmd_append,
    "chart": cmd_chart,
    "inputlookup": cmd_inputlookup,
    "join": cmd_join,
    "lookup": cmd_lookup,
    "tstats": cmd_tstats,
}

__all__ = [
    "HANDLERS",
    "INDEXED_FIELDS",
    "INHERITED_FIELDS",
    "MAX_APPEND_ROWS",
    "MAX_RESULT_ROWS",
    "MAX_APPENDED_TOTAL",
    "MAX_JOIN_ROWS",
    "MAX_SUBSEARCHES",
    "MAX_SUBSEARCH_DEPTH",
    "SubsearchFailedError",
    "inputlookup_appends",
    "tstats_appends",
]
