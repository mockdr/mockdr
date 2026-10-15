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
from utils.splunk.response import build_splunk_entry, build_splunk_envelope, complete
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


# ── The REST view: data/transforms/lookups ─────────────────────────────────

_TRANSFORMS = "data/transforms/lookups"

#: What every transforms.conf stanza reports beside its own settings comes
#: from a 10.4.2 recording (``infrastructure/fixtures/splunk/lookup_transform.json``,
#: an external lookup). The external lookup's own members are left out of a
#: kvstore or file definition, which has none of them.
_EXTERNAL_ONLY = ("external_cmd", "python.required", "fields_array", "fields_list", "type")

#: A definition created over REST can be moved and removed; one a .conf file
#: ships offers neither link — dnslookup, geo_attr_countries (measured on
#: splunkd 10.4.2).
_LINKS = ("_reload", "alternate", "disable", "edit", "list", "move", "remove")
_SHIPPED_LINKS = ("_reload", "alternate", "disable", "edit", "list")


def definition_content(definition: LookupDefinition) -> dict:
    """A definition's content block, as ``data/transforms/lookups`` lists it."""
    content = {k: v for k, v in complete({}, "lookup_transform").items()
               if k not in _EXTERNAL_ONLY}
    content |= {"eai:appName": definition.app, "eai:userName": definition.owner}
    # A kvstore definition reports `type: kvstore`, and one without a
    # fields_list reports it null over an empty array; a file definition
    # lists its CSV header as both (all measured on splunkd 10.4.2).
    if definition.collection:
        fields = list(definition.fields_list)
        content |= {
            "collection": definition.collection,
            "external_type": "kvstore",
            "fields_array": fields,
            "fields_list": ",".join(fields) if fields else None,
            "type": "kvstore",
        }
    else:
        found = lookup_file_repo.find(definition.filename)
        header = list(found.header) if found is not None else []
        content |= {
            "fields_array": header,
            "fields_list": ",".join(header) if header else None,
            "filename": definition.filename,
            "type": "file",
        }
    content |= definition.explicit
    return content


#: What a single read of a definition says it accepts; the listing and the
#: create answer carry no ``fields`` block (measured on splunkd 10.4.2).
_DEFINITION_FIELDS = {
    "required": [],
    "optional": [
        "allow_caching", "batch_index_query", "cache_size", "case_sensitive_match",
        "check_permission", "collection", "default_match", "disabled",
        "event_time_field", "external_cmd", "external_type", "feature_id_element",
        "fields_list", "filename", "filter", "index_fields_list", "match_type",
        "max_duplicates", "max_ext_batch", "max_matches", "max_offset_secs",
        "min_matches", "min_offset_secs",
        "reverse_lookup_honor_case_sensitive_match", "time_field", "time_format",
    ],
    "wildcard": [],
}

#: A definition made over REST is its creator's: splunkd reports it authored
#: and owned by them, re-shareable to user level, removable, and writable by
#: admin and power (measured on splunkd 10.4.2).
_CREATED_ACL = {
    "can_share_user": True,
    "removable": True,
    "perms": {"read": ["*"], "write": ["admin", "power"]},
}


def definition_entry(definition: LookupDefinition) -> dict:
    """One lookup definition as an Atom entry, under the app that holds it."""
    owner = definition.creator or definition.owner
    return build_splunk_entry(
        definition.name,
        definition_content(definition),
        collection=_TRANSFORMS,
        links=_LINKS if definition.creator else _SHIPPED_LINKS,
        fields=False,
        author=owner,
        # Shared globally, as Enterprise Security shares its lookups — and as
        # splunkd shares one created over REST.
        acl_extra={"app": definition.app, "owner": owner,
                   "sharing": "global", "perms": {"read": ["*"], "write": ["admin"]},
                   **(_CREATED_ACL if definition.creator else {})},
    )


def list_definitions() -> dict:
    """Every lookup definition, by name."""
    definitions = sorted(lookup_definition_repo.list_all(), key=lambda d: (d.name, d.app))
    return transforms_envelope([definition_entry(d) for d in definitions])


def get_definition(name: str) -> dict | None:
    """One lookup definition, or None."""
    definition = lookup_definition_repo.find(name)
    if definition is None:
        return None
    # A read by name names what the stanza accepts; the listing does not.
    return transforms_envelope([{**definition_entry(definition), "fields": _DEFINITION_FIELDS}])


def list_lookup_files() -> dict:
    """The CSV lookup table files, as ``data/lookup-table-files`` lists them."""
    entries = [
        build_splunk_entry(
            found.name,
            complete({
                "eai:appName": found.app,
                "eai:data": f"/opt/splunk/etc/apps/{found.app}/lookups/{found.name}",
                "eai:userName": found.owner,
            }, "lookup_file"),
            collection=_FILES,
            links=("_reload", "alternate", "edit", "list", "move", "remove"),
            fields=False,
            acl_extra={"app": found.app, "owner": found.owner, "sharing": "global",
                       "perms": {"read": ["*"], "write": ["admin"]}},
        )
        for found in sorted(lookup_file_repo.list_all(), key=lambda f: (f.name, f.app))
    ]
    return transforms_envelope(entries, _FILES)


_FILES = "data/lookup-table-files"


def transforms_envelope(entries: list[dict], collection: str = _TRANSFORMS) -> dict:
    """The collection envelope, with the links a knowledge collection offers."""
    path = f"/services/{collection}"
    return build_splunk_envelope(
        entries, origin=path,
        links={"_acl": f"{path}/_acl", "_reload": f"{path}/_reload",
               "create": f"{path}/_new"},
    )
