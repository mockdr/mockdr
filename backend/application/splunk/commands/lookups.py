"""Creating and removing lookup definitions (``data/transforms/lookups``).

A test that wants `| lookup` or `| inputlookup` over a table of its own
creates the KV Store collection, fills it, and then defines the lookup — the
REST reference's ``POST data/transforms/lookups`` with ``name``,
``external_type=kvstore``, ``collection`` and ``fields_list`` (or
``filename`` for a CSV file).
"""
from __future__ import annotations

from domain.splunk.lookup import LookupDefinition
from repository.splunk.lookup_repo import lookup_definition_repo


class LookupDefinitionError(ValueError):
    """A definition splunkd would not create; the HTTP status rides along."""

    def __init__(self, message: str, status: int = 400) -> None:
        """Record the refusal and the status it is answered with."""
        super().__init__(message)
        self.status = status


def _flag(raw: str) -> bool:
    return raw.strip().lower() in ("1", "t", "true", "y", "yes")


def _count(name: str, raw: str) -> int:
    text = raw.strip()
    if not text.isdigit():
        msg = f"Invalid value for {name}: '{raw}'"
        raise LookupDefinitionError(msg)
    return int(text)


def create_definition(params: dict[str, str], app: str, owner: str) -> LookupDefinition:
    """Define a lookup from the parameters splunkd takes for one.

    Raises:
        LookupDefinitionError: Without a name (400), with a name already
            defined (409), or naming neither a collection nor a file (400).
    """
    name = params.get("name", "").strip()
    if not name:
        msg = 'Cannot perform action "POST" without a target name to act on.'
        raise LookupDefinitionError(msg)
    if lookup_definition_repo.find(name) is not None:
        msg = f"An object with name={name} already exists"
        raise LookupDefinitionError(msg, status=409)
    collection = params.get("collection", "").strip()
    filename = params.get("filename", "").strip()
    external_type = params.get("external_type", "").strip().lower()
    if collection and external_type not in ("", "kvstore"):
        msg = f"Invalid value for external_type: '{external_type}'"
        raise LookupDefinitionError(msg)
    if bool(collection) == bool(filename):
        msg = "A lookup definition needs exactly one of 'filename' and 'collection'."
        raise LookupDefinitionError(msg)
    definition = LookupDefinition(
        name=name, app=app, owner=owner,
        collection=collection, filename=filename,
        fields_list=[f.strip() for f in params.get("fields_list", "").split(",") if f.strip()],
    )
    if "case_sensitive_match" in params:
        definition.case_sensitive_match = _flag(params["case_sensitive_match"])
    if "max_matches" in params:
        definition.max_matches = max(1, min(_count("max_matches", params["max_matches"]), 1000))
    if "min_matches" in params:
        definition.min_matches = _count("min_matches", params["min_matches"])
    if "default_match" in params:
        definition.default_match = params["default_match"]
    lookup_definition_repo.save(definition)
    return definition


def delete_definition(name: str) -> bool:
    """Remove a lookup definition by name; False if there was none."""
    definition = lookup_definition_repo.find(name)
    if definition is None:
        return False
    return lookup_definition_repo.delete(definition.id)
