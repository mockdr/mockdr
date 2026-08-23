"""Network identifiers for seed data that can never point at a real third party.

Faker's ``ipv4_public()`` draws routable addresses and ``domain_name()``
surname-based domains that are often registered; a demo "IOC" or "external
IP" built from them names somebody's real host. Seed data uses the ranges
and top-level domains reserved for documentation instead (RFC 5737,
RFC 2606/6761): ``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``
and ``*.example`` / ``*.test``.
"""

from __future__ import annotations

import random

_DOC_NETS = ("192.0.2", "198.51.100", "203.0.113")
_WORDS = (
    "updates", "cdn", "files", "mail", "login", "portal", "static", "api",
    "secure", "assets", "download", "support", "sync", "status", "auth",
    "billing", "docs", "media", "cloud", "edge",
)
_LABELS = (
    "northwind", "contoso", "fabrikam", "litware", "adatum", "tailspin",
    "wingtip", "woodgrove", "proseware", "alpineski", "lucerne", "coho",
    "relecloud", "bellows", "margies", "vanarsdel", "humongous", "trey",
)


def doc_ipv4() -> str:
    """A routable-looking address from a documentation range."""
    return f"{random.choice(_DOC_NETS)}.{random.randint(1, 254)}"  # noqa: S311


def doc_domain(subdomain: bool = False) -> str:
    """A plausible domain under a reserved top-level domain (``.example``/``.test``)."""
    host = f"{random.choice(_LABELS)}.{random.choice(('example', 'test'))}"  # noqa: S311
    return f"{random.choice(_WORDS)}.{host}" if subdomain else host  # noqa: S311


def doc_email(local: str, host: str = "personal-mail.example") -> str:
    """An address that cannot be delivered anywhere real."""
    return f"{local}@{host}"
