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


def doc_ipv4(rng: random.Random | None = None) -> str:
    """A routable-looking address from a documentation range.

    Args:
        rng: The generator to draw from; the shared seeded one when omitted.
    """
    r = rng or random
    return f"{r.choice(_DOC_NETS)}.{r.randint(1, 254)}"  # noqa: S311


def doc_domain(subdomain: bool = False, rng: random.Random | None = None) -> str:
    """A plausible domain under a reserved top-level domain (``.example``/``.test``).

    Args:
        subdomain: Prefix a host label (``cdn.contoso.test``).
        rng: The generator to draw from; the shared seeded one when omitted.
    """
    r = rng or random
    host = f"{r.choice(_LABELS)}.{r.choice(('example', 'test'))}"  # noqa: S311
    return f"{r.choice(_WORDS)}.{host}" if subdomain else host  # noqa: S311


def doc_url(rng: random.Random | None = None) -> str:
    """A URL on a reserved domain, with a path, as an indicator feed carries it."""
    r = rng or random
    path = r.choice(_WORDS)  # noqa: S311
    return f"https://{doc_domain(subdomain=True, rng=rng)}/{path}/"
