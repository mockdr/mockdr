"""What an index says its fields are, and what Elasticsearch infers.

mockdr took a client's ``mappings`` on ``PUT /{index}`` and threw them away:
``GET /{index}`` answered ``"mappings": {}`` where a cluster echoes back what
it was given, and ``_field_caps`` — which every Kibana data view asks for
before it can draw anything — was not served at all.

A cluster also *adds* to the mapping as documents arrive, and the types it
picks are not obvious: a string becomes ``text`` with a ``.keyword`` subfield
capped at 256 characters, a string that parses as a date becomes ``date``, a
whole number becomes ``long`` and a fractional one ``float``, an array takes
its element's type, and an object becomes nested ``properties``. All measured
against Elasticsearch 8.15.

The types matter beyond the mapping API: a ``terms`` aggregation over a
``text`` field is an error on a real cluster, because fielddata is off.
"""
from __future__ import annotations

import re
from typing import Any

__all__ = [
    "field_capabilities",
    "flatten_properties",
    "infer_properties",
    "merge_properties",
]

#: The subfield Elasticsearch hangs off every dynamically mapped string.
_KEYWORD_SUBFIELD = {"keyword": {"type": "keyword", "ignore_above": 256}}

#: What dynamic date detection accepts: ISO-8601, with or without a zone.
_DATE_LIKE = re.compile(
    r"\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$",
)

#: Field types that can be grouped or ordered. `text` is the one that looks
#: like it should be and is not — its terms are analysed, and fielddata is
#: off by default, so a cluster refuses to aggregate on it.
_AGGREGATABLE = frozenset({
    "keyword", "long", "integer", "short", "byte", "double", "float",
    "half_float", "scaled_float", "date", "boolean", "ip", "constant_keyword",
    "version",
})


def infer_properties(source: dict) -> dict:
    """The mapping Elasticsearch would add for this document."""
    properties: dict[str, Any] = {}
    for name, value in source.items():
        mapped = _infer_field(value)
        if mapped is not None:
            properties[name] = mapped
    return properties


def _infer_field(value: Any) -> dict | None:
    """The type a single value maps to, or None when it maps to nothing."""
    if isinstance(value, (list, tuple)):
        # An array takes its first non-null element's type; an empty one
        # indexes nothing and so maps to nothing.
        for item in value:
            mapped = _infer_field(item)
            if mapped is not None:
                return mapped
        return None
    if value is None:
        return None
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "long"}
    if isinstance(value, float):
        return {"type": "float"}
    if isinstance(value, dict):
        return {"properties": infer_properties(value)}
    if isinstance(value, str):
        if _DATE_LIKE.fullmatch(value):
            return {"type": "date"}
        return {"type": "text", "fields": dict(_KEYWORD_SUBFIELD)}
    return {"type": "text", "fields": dict(_KEYWORD_SUBFIELD)}


class MappingConflictError(ValueError):
    """Raised when a mapping update would change a field's type.

    Elasticsearch refuses it — the data is already indexed under the old
    type — and says which field and which two types in so many words.
    """

    def __init__(self, field: str, old: str, new: str) -> None:
        """Record the field and the two types."""
        self.field = field
        super().__init__(f"mapper [{field}] cannot be changed from type [{old}] to [{new}]")


def merge_properties(
    existing: dict, incoming: dict, *, strict: bool = False, path: str = "",
) -> dict:
    """Merge *incoming* properties into *existing*.

    Args:
        existing: The properties already mapped.
        incoming: The properties to add.
        strict:   Refuse a type change, as ``PUT /{index}/_mapping`` does.
                  Dynamic mapping never changes a type, so it does not need
                  this; a client asking for one has to be told no.
        path:     The dotted name of the parent, for the error message.

    Returns:
        The merged properties.

    Raises:
        MappingConflictError: If *strict* and a field's type would change.
    """
    merged = dict(existing)
    for name, spec in incoming.items():
        full = f"{path}.{name}" if path else name
        current = merged.get(name)
        if not isinstance(current, dict):
            merged[name] = spec
            continue
        if "properties" in current or "properties" in spec:
            merged[name] = {
                **current,
                "properties": merge_properties(
                    current.get("properties", {}), spec.get("properties", {}),
                    strict=strict, path=full,
                ),
            }
            continue
        old, new = current.get("type"), spec.get("type")
        if strict and new and old and new != old:
            raise MappingConflictError(full, str(old), str(new))
        # A field already mapped keeps the type it has: the documents are
        # indexed under it.
        merged[name] = current
    return merged


def flatten_properties(properties: dict, prefix: str = "") -> dict[str, dict]:
    """Every field the mapping declares, by its dotted name.

    An object is listed itself — ``_field_caps`` reports it as type
    ``object`` — and so is each field beneath it.
    """
    flat: dict[str, dict] = {}
    for name, spec in properties.items():
        full = f"{prefix}.{name}" if prefix else name
        if "properties" in spec:
            flat[full] = {"type": "object"}
            flat.update(flatten_properties(spec["properties"], full))
            continue
        flat[full] = spec
        for sub_name, sub_spec in (spec.get("fields") or {}).items():
            flat[f"{full}.{sub_name}"] = sub_spec
    return flat


#: The fields every index carries whatever its mapping says. A Kibana data
#: view lists them, so `fields: "*"` has to include them; each entry is
#: exactly what Elasticsearch 8.15 reports for it.
_METADATA_FIELDS: dict[str, tuple[str, bool, bool]] = {
    # name: (type, searchable, aggregatable)
    "_data_stream_timestamp": ("_data_stream_timestamp", False, False),
    "_doc_count": ("integer", False, False),
    "_feature": ("_feature", False, False),
    "_field_names": ("_field_names", True, False),
    "_id": ("_id", True, False),
    "_ignored": ("_ignored", True, True),
    "_ignored_source": ("_ignored_source", False, False),
    "_index": ("_index", True, True),
    "_nested_path": ("_nested_path", True, False),
    "_routing": ("_routing", True, False),
    "_seq_no": ("_seq_no", True, True),
    "_source": ("_source", False, False),
    "_tier": ("keyword", True, True),
    "_version": ("_version", False, True),
}


def field_capabilities(properties: dict, wanted: list[str]) -> dict:
    """The ``_field_caps`` body for these properties.

    Every field is searchable; only the types a cluster can build doc values
    for are aggregatable, which is why a ``text`` field comes back
    ``aggregatable: false`` and its ``.keyword`` subfield does not.
    """
    flat = flatten_properties(properties)
    fields: dict[str, Any] = {}
    for name, spec in flat.items():
        if wanted and not any(_wanted(name, w, flat) for w in wanted):
            continue
        kind = str(spec.get("type", "object"))
        fields[name] = {kind: {
            "type": kind,
            "metadata_field": False,
            "searchable": kind != "object",
            "aggregatable": kind in _AGGREGATABLE,
        }}
    for name, (kind, searchable, aggregatable) in _METADATA_FIELDS.items():
        if wanted and not any(_name_matches(name, w) for w in wanted):
            continue
        fields[name] = {kind: {
            "type": kind,
            "metadata_field": True,
            "searchable": searchable,
            "aggregatable": aggregatable,
        }}
    return fields


def _wanted(name: str, pattern: str, flat: dict[str, dict]) -> bool:
    """Whether this field is asked for, directly or as an object above one.

    Asking for `obj.a` gets `obj` too: a cluster reports the object a field
    sits in alongside the field itself.
    """
    if _name_matches(name, pattern):
        return True
    return pattern.startswith(f"{name}.") and "properties" not in flat.get(name, {})


def _name_matches(name: str, pattern: str) -> bool:
    if pattern in ("*", ""):
        return True
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def is_aggregatable(properties: dict, field: str) -> bool | None:
    """Whether a ``terms``-style aggregation can read this field.

    Returns None when the mapping says nothing about it, which is how a
    caller tells "not aggregatable" from "not mapped".
    """
    spec = flatten_properties(properties).get(field)
    if spec is None:
        return None
    return str(spec.get("type", "object")) in _AGGREGATABLE
