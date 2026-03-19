"""Map request paths to vendor names based on URL prefix."""
from __future__ import annotations

# Ordered by specificity -- longer prefixes first to avoid false matches.
_PREFIX_MAP: list[tuple[str, str]] = [
    ("/web/api/v2.1", "s1"),
    ("/xdr/public_api/v1", "cortex_xdr"),
    ("/kibana/", "elastic"),
    ("/elastic/", "elastic"),
    ("/cs/", "crowdstrike"),
    ("/mde/", "mde"),
    ("/splunk/", "splunk"),
    ("/sentinel/", "sentinel"),
    ("/graph/", "graph"),
]

# The mockdr prefix to strip before forwarding to the real vendor API.
# S1 uses the same path in both mockdr and the real API, so nothing is stripped.
VENDOR_STRIP_PREFIX: dict[str, str] = {
    "s1": "",                    # real API also uses /web/api/v2.1
    "crowdstrike": "/cs",
    "mde": "/mde",
    "elastic": "/elastic",
    "cortex_xdr": "/xdr/public_api/v1",
    "splunk": "/splunk",
    "sentinel": "/sentinel",
    "graph": "/graph",
}

# Kibana is a second prefix for the elastic vendor.
_KIBANA_STRIP = "/kibana"


def detect_vendor(path: str) -> str | None:
    """Return the vendor name for a request path, or ``None`` if unrecognized."""
    for prefix, vendor in _PREFIX_MAP:
        if path.startswith(prefix):
            return vendor
    return None


def strip_prefix(path: str, vendor: str) -> str:
    """Remove the mockdr vendor prefix from *path* for upstream forwarding.

    For S1 the path is returned as-is (real API uses the same prefix).
    For Elastic/Kibana, ``/kibana`` is also handled.
    """
    if vendor == "elastic" and path.startswith(_KIBANA_STRIP):
        return path[len(_KIBANA_STRIP):]
    prefix = VENDOR_STRIP_PREFIX.get(vendor, "")
    if prefix and path.startswith(prefix):
        return path[len(prefix):]
    return path
