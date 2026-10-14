"""ARM resource names are case-insensitive.

Azure Resource Manager matches the segments of a resource path without
regard to case — the reference pages say so of the resource group ("The name
is case insensitive"), and the rule is ARM's for every resource name. A
client that read an incident as `ABC-123` and wrote it back as `abc-123`
addresses the same incident; the mock's store matched names exactly, so the
read answered 404 and the write created a second incident beside the first.

These repositories find a record by its exact key first and, failing that,
by a case-insensitive match, so a lookup, an update and a delete all reach
the record under the name it was created with.
"""
from __future__ import annotations

from typing import Generic, TypeVar

from repository.base import Repository
from repository.store import store

T = TypeVar("T")


class CaseInsensitiveRepository(Repository[T], Generic[T]):
    """A repository whose keys are ARM names: matched without regard to case."""

    def _stored_key(self, id: str) -> str | None:
        """The key a record is stored under, matched exactly or else ignoring case."""
        if store.exists(self._collection, id):
            return id
        folded = id.casefold()
        return next(
            (key for key in store.get_all_with_keys(self._collection)
             if key.casefold() == folded),
            None,
        )

    def get(self, id: str) -> T | None:
        """Return the record named ``id``, in any case, or None."""
        key = self._stored_key(id)
        return store.get(self._collection, key) if key is not None else None

    def delete(self, id: str) -> bool:
        """Delete the record named ``id``, in any case."""
        key = self._stored_key(id)
        return store.delete(self._collection, key) if key is not None else False

    def exists(self, id: str) -> bool:
        """Whether a record named ``id``, in any case, exists."""
        return self._stored_key(id) is not None
