"""Path parameters that must not swallow a sibling endpoint.

``/services/search/jobs/{sid}`` and ``/services/search/jobs/export`` are two
endpoints, and a parameter that matches anything matches the second as well:
``DELETE …/jobs/export`` was read as "delete the job with sid `export`" and
answered 404 `Unknown sid` where splunkd answers 405 `Allow: POST`. The KV
store has the same pair in ``…/data/{name}/{key}`` against ``batch_find``
and ``batch_save``, and Elasticsearch has it in ``/{index}`` against every
one of its underscore-prefixed endpoints.

A route convertor is the honest place to say so: the parameter *does not
match* the reserved name, so the request falls through to the endpoint that
owns it — or, where the verb is wrong, to the unmatched-route fallback, which
answers as the product does.
"""

from __future__ import annotations

from starlette.convertors import Convertor, register_url_convertor


class _Excluding(Convertor[str]):
    """A path segment that is anything but the names an endpoint has claimed."""

    #: Set by each subclass; the regex is built from it.
    reserved: tuple[str, ...] = ()

    def convert(self, value: str) -> str:
        return value

    def to_string(self, value: str) -> str:
        return value


class SearchJobSid(_Excluding):
    """A search job's sid, which is never ``export``."""

    regex = r"(?!export(?=[/?]|$))[^/]+"


class KvStoreKey(_Excluding):
    """A KV store record key, which is never one of the batch endpoints."""

    regex = r"(?!batch_(?:find|save)(?=[/?]|$))[^/]+"


class EsIndexName(_Excluding):
    """An index name, which Elasticsearch forbids from starting with ``_``.

    ``_all`` is the documented exception: it names every index rather than
    one, and the mock's own error message for the rest — "must not start with
    '_'" — is the rule stated by the product itself.
    """

    regex = r"(?!_(?!all(?=[/?]|$)))[^/]+"


def register() -> None:
    """Make the convertors available to every router's path declarations."""
    register_url_convertor("splunksid", SearchJobSid())
    register_url_convertor("kvkey", KvStoreKey())
    register_url_convertor("esindex", EsIndexName())
