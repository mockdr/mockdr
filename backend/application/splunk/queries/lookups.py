"""Resolving a lookup name to the table a search reads.

A name is looked up as a lookup definition first (transforms.conf): a
kvstore definition reads its ``collection``, a file definition its
``filename``. A name ending in ``.csv`` that no definition claims is read as
a lookup table file directly, which ``inputlookup`` allows and ``lookup``
does too (lookup command reference: "a lookup table file name").
"""
from __future__ import annotations

from domain.splunk.kv_collection import KVCollection
from domain.splunk.lookup import LookupDefinition
from repository.splunk.kv_collection_repo import kv_collection_repo
from repository.splunk.lookup_repo import lookup_definition_repo, lookup_file_repo
from utils.splunk.spl_sources import LookupTable

#: ``[kvstore] max_rows_per_query``: the most records one read of a
#: collection returns, 50,000 by default (limits.conf).
MAX_KV_ROWS = 50_000


def resolve_lookup(name: str) -> LookupTable | None:
    """The table *name* stands for, or None when there is none."""
    definition = lookup_definition_repo.find(name)
    if definition is not None:
        return _from_definition(definition)
    if name.lower().endswith(".csv"):
        found = lookup_file_repo.find(name)
        if found is not None:
            return LookupTable(
                name=name, fields=list(found.header), rows=[dict(r) for r in found.rows],
            )
    return None


def _collection(name: str, app: str) -> KVCollection | None:
    """The collection a definition names: in its own app first, then any."""
    own = kv_collection_repo.get_by_name(name, app)
    if own is not None:
        return own
    return next((c for c in kv_collection_repo.list_all() if c.name == name), None)


def _from_definition(definition: LookupDefinition) -> LookupTable | None:
    if definition.collection:
        collection = _collection(definition.collection, definition.app)
        if collection is None:
            return None
        fields = list(definition.fields_list) or ["_key", *collection.field_types]
        rows = [dict(record) for record in collection.records[:MAX_KV_ROWS]]
    else:
        found = lookup_file_repo.find(definition.filename)
        if found is None:
            return None
        fields, rows = list(found.header), [dict(row) for row in found.rows]
    return LookupTable(
        name=definition.name, fields=fields, rows=rows,
        max_matches=definition.max_matches,
        min_matches=definition.min_matches,
        default_match=definition.default_match,
        case_sensitive_match=definition.case_sensitive_match,
    )

