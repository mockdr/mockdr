"""Where the mock may send a request of its own.

Two features make mockdr an HTTP client: the recording proxy (forwarding to a
real vendor, and fetching that vendor's OAuth token) and outbound webhooks.
Both take their target from an API call, and the admin token that makes the
call is a documented constant — so the target is, in effect, chosen by
whoever can reach the mock.

Every target is held to two rules here:

* ``http`` or ``https`` with a host, nothing else;
* never a link-local or metadata address. ``169.254.0.0/16`` and
  ``fe80::/10`` are where cloud metadata services answer (AWS, GCP, Azure;
  AWS's IPv6 endpoint is ``fd00:ec2::254``), and handing their credentials to
  a caller is the classic SSRF payoff. No vendor API or webhook receiver
  lives there.

Loopback and private ranges stay reachable: a test's receiver on localhost
and a lab Splunk on 10.x are what the features are for. On a public instance
(``MOCKDR_PUBLIC``) no outbound request is made at all — see ``config``.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import config

#: Addresses that answer as a cloud metadata service outside link-local.
_METADATA_ADDRESSES = frozenset({
    ipaddress.ip_address("fd00:ec2::254"),    # AWS IMDS over IPv6
    ipaddress.ip_address("100.100.100.200"),  # Alibaba Cloud metadata
})


class EgressRefusedError(ValueError):
    """The target is not one the mock will send a request to."""


def _refused_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether *addr* is link-local, unspecified or a metadata endpoint."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return _refused_address(addr.ipv4_mapped)
    return addr.is_link_local or addr.is_unspecified or addr in _METADATA_ADDRESSES


def check_outbound_url(url: str, *, resolve: bool = True) -> None:
    """Raise :class:`EgressRefusedError` unless the mock may send a request to *url*.

    Args:
        url: The absolute target URL.
        resolve: Also resolve the host name and refuse it when any address it
            resolves to is refused. Callers check again right before each
            request, so a name re-pointed after configuration is caught there.
    """
    if config.PUBLIC_MODE:
        raise EgressRefusedError(
            "outbound requests are disabled on a public instance (MOCKDR_PUBLIC)",
        )
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise EgressRefusedError(f"not an http(s) URL with a host: {url!r}")
    host = parts.hostname
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
    if literal is not None:
        if _refused_address(literal):
            raise EgressRefusedError(f"refusing link-local or metadata address {host}")
        return
    if not resolve:
        return
    try:
        infos = socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError):
        # Unresolvable: the request itself fails and says so.
        return
    for info in infos:
        try:
            addr = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        except ValueError:
            continue
        if _refused_address(addr):
            raise EgressRefusedError(
                f"{host} resolves to link-local or metadata address {addr}",
            )
