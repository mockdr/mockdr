"""Elasticsearch REST API query handlers for the mock server.

Routes search requests to the appropriate in-memory collection based on the
index pattern, applies Elasticsearch query DSL, and returns standard ES
response envelopes.
"""
from __future__ import annotations

from dataclasses import asdict

from repository.es_alert_repo import es_alert_repo
from repository.es_endpoint_repo import es_endpoint_repo
from utils.es_query import _build_predicate, apply_es_query, wrap_as_hits
from utils.es_response import build_es_search_response

# ── Index pattern routing ────────────────────────────────────────────────────

class IndexNotFoundError(LookupError):
    """Raised when a concrete index does not exist.

    Elasticsearch answers a missing *concrete* index with ``404
    index_not_found_exception``; returning an empty result set instead would
    tell a caller the index exists and holds nothing, which is a different
    fact and one they cannot act on.
    """

    def __init__(self, index: str) -> None:
        """Record the index name so the 404 body can name it."""
        self.index = index
        super().__init__(f"no such index [{index}]")


#: Index-name prefixes this mock actually backs, grouped by their source.
_ALERT_PREFIXES: tuple[str, ...] = (".siem-signals", ".alerts-security")
_ENDPOINT_PREFIXES: tuple[str, ...] = ("metrics-endpoint", "logs-endpoint")
_KNOWN_PREFIXES: tuple[str, ...] = _ALERT_PREFIXES + _ENDPOINT_PREFIXES


def _pattern_hits(name: str, prefixes: tuple[str, ...]) -> bool:
    """Return whether an index expression selects any of *prefixes*.

    A trailing wildcard is compared against the literal part on both sides, so
    ``logs-*`` selects ``logs-endpoint`` and ``.siem-signals-*`` selects
    ``.siem-signals`` — the mock stores prefixes where a real cluster would
    hold dated concrete names.
    """
    if name in ("_all", "*"):
        return True
    if "*" in name:
        literal = name.split("*", 1)[0]
        return any(p.startswith(literal) or literal.startswith(p) for p in prefixes)
    return name.startswith(prefixes)


def _missing_target(index: str) -> str | None:
    """Return the first target in *index* that cannot be resolved.

    Elasticsearch accepts a comma-separated list of targets and only refuses
    the ones it must: a *concrete* name that does not exist. A wildcard, or the
    ``_all`` alias, resolving to nothing is governed by ``allow_no_indices``,
    which defaults to true — so those stay a 200 with no hits rather than a
    404. Conflating the two would make a legitimate empty search look broken.

    Args:
        index: Raw index expression from the request path.

    Returns:
        The offending target name, or ``None`` when every target is resolvable.
    """
    for target in index.split(","):
        name = target.strip().lower()
        if not name or name == "_all" or "*" in name:
            continue
        if not name.startswith(_KNOWN_PREFIXES):
            return target.strip()
    return None


def known_index_prefixes() -> tuple[str, ...]:
    """Return the index prefixes this mock serves, for docs and diagnostics."""
    return _KNOWN_PREFIXES


def _resolve_collection(index: str, *, ignore_unavailable: bool = False) -> tuple[list[dict], str]:
    """Resolve an index pattern to the backing in-memory collection.

    Args:
        index:              Elasticsearch index name or pattern.
        ignore_unavailable: Skip missing concrete targets instead of failing,
                            mirroring the query parameter of the same name.

    Returns:
        Tuple of (records as dicts, canonical index name).

    Raises:
        IndexNotFoundError: If a concrete index name is unknown.
    """
    idx = index.lower()

    if not ignore_unavailable:
        missing = _missing_target(index)
        if missing is not None:
            raise IndexNotFoundError(missing)

    names = [t.strip().lower() for t in idx.split(",") if t.strip()]
    records: list[dict] = []
    if any(_pattern_hits(n, _ALERT_PREFIXES) for n in names):
        records += [asdict(a) for a in es_alert_repo.list_all()]
    if any(_pattern_hits(n, _ENDPOINT_PREFIXES) for n in names):
        records += [asdict(ep) for ep in es_endpoint_repo.list_all()]
    return records, idx


# ── Public query functions ───────────────────────────────────────────────────

def es_search(index: str, body: dict, *, ignore_unavailable: bool = False) -> dict:
    """Execute an Elasticsearch _search against the mock data.

    Args:
        index:              Target index name or pattern.
        body:               Elasticsearch query DSL request body.
        ignore_unavailable: Skip a missing concrete index instead of failing.

    Returns:
        Full Elasticsearch _search response envelope.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown.
    """
    records, canonical_index = _resolve_collection(
        index, ignore_unavailable=ignore_unavailable,
    )

    # Capture total before pagination.
    total_before = len(records)

    # Apply query DSL (filter, sort, from/size).
    filtered = apply_es_query(records, body)

    # If a query clause was provided, the total is the filtered count
    # before from/size pagination; otherwise it's all records.
    query_clause = body.get("query")
    if query_clause:
        # Re-filter without pagination to get the true total.
        predicate = _build_predicate(query_clause)
        total = sum(1 for r in records if predicate(r))
    else:
        total = total_before

    hits = wrap_as_hits(filtered, index=canonical_index)
    return build_es_search_response(hits, total)


def es_get_doc(index: str, doc_id: str) -> dict | None:
    """Get a single document by ID from the appropriate collection.

    Args:
        index:  Target index name or pattern.
        doc_id: Document ID.

    Returns:
        Elasticsearch get response dict, or None if not found.
    """
    records, canonical_index = _resolve_collection(index)

    for rec in records:
        if rec.get("id") == doc_id:
            return {
                "_index": canonical_index,
                "_id": doc_id,
                "_version": 1,
                "_seq_no": 0,
                "_primary_term": 1,
                "found": True,
                "_source": rec,
            }

    return None


def es_get_mapping(index: str) -> dict:
    """Return a canned index mapping for known index patterns.

    Args:
        index: Target index name or pattern.

    Returns:
        Elasticsearch mapping response dict.

    Raises:
        IndexNotFoundError: If a concrete index name is unknown, as ``_search``
            and ``_stats`` already do — answering an empty mapping instead said
            the index existed and had no fields.
    """
    missing = _missing_target(index)
    if missing is not None:
        raise IndexNotFoundError(missing)

    idx = index.lower()

    if idx.startswith(".siem-signals") or idx.startswith(".alerts-security"):
        properties = {
            "@timestamp": {"type": "date"},
            "signal.rule.id": {"type": "keyword"},
            "signal.rule.name": {"type": "keyword"},
            "signal.status": {"type": "keyword"},
            "kibana.alert.severity": {"type": "keyword"},
            "kibana.alert.workflow_status": {"type": "keyword"},
            "agent.id": {"type": "keyword"},
            "host.name": {"type": "keyword"},
        }
    elif idx.startswith("metrics-endpoint") or idx.startswith("logs-endpoint"):
        properties = {
            "@timestamp": {"type": "date"},
            "agent.id": {"type": "keyword"},
            "agent.status": {"type": "keyword"},
            "host.hostname": {"type": "keyword"},
            "host.os.name": {"type": "keyword"},
            "host.os.platform": {"type": "keyword"},
            "host.ip": {"type": "ip"},
        }
    else:
        properties = {}

    return {
        index: {
            "mappings": {
                "properties": properties,
            },
        },
    }


def es_get_stats(index: str) -> dict:
    """Return canned index stats for known index patterns.

    Args:
        index: Target index name or pattern.

    Returns:
        Elasticsearch index stats response dict.
    """
    records, _ = _resolve_collection(index)
    doc_count = len(records)

    return {
        "_shards": {"total": 1, "successful": 1, "failed": 0},
        "_all": {
            "primaries": {
                "docs": {"count": doc_count, "deleted": 0},
                "store": {"size_in_bytes": doc_count * 1024},
            },
            "total": {
                "docs": {"count": doc_count, "deleted": 0},
                "store": {"size_in_bytes": doc_count * 1024},
            },
        },
        "indices": {
            index: {
                "primaries": {
                    "docs": {"count": doc_count, "deleted": 0},
                    "store": {"size_in_bytes": doc_count * 1024},
                },
                "total": {
                    "docs": {"count": doc_count, "deleted": 0},
                    "store": {"size_in_bytes": doc_count * 1024},
                },
            },
        },
    }


def cluster_info() -> dict:
    """Return mock Elasticsearch cluster info (version 8.x).

    Returns:
        Elasticsearch cluster info response dict.
    """
    return {
        "name": "mock-es-node-01",
        "cluster_name": "mockdr-elastic",
        "cluster_uuid": "mock-cluster-uuid-0001",
        "version": {
            "number": "8.12.0",
            "build_flavor": "default",
            "build_type": "docker",
            "build_hash": "abc123mock",
            "build_date": "2024-01-01T00:00:00.000Z",
            "build_snapshot": False,
            "lucene_version": "9.9.1",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }
