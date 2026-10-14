"""Seeded indicators and hosts never name somebody's real infrastructure.

`infrastructure/safe_net.py` promises it: documentation address ranges and
reserved TLDs only. S1's DNS and URL indicators came from Faker's
`domain_name()` and `url()` — `jefferson.com`, `white-morales.info`, often
registered domains — filed as malicious. Cortex's indicators were a Tor exit,
`scanme.nmap.org`'s address and six domains under real TLDs, and
Defender's IP indicators sat in real networks, Tor exits among them. Its audit log
named hosts from `fake.hostname()`: real TLDs again, and no endpoint the
tenant has. A client that blocks or enriches what the seed reports would
act on real third parties.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

_RESERVED_TLDS = ("example", "test", "invalid", "localhost")


def _reserved_host(name: str) -> bool:
    return name.rstrip(".").rsplit(".", 1)[-1] in _RESERVED_TLDS


def _violations() -> list[str]:
    from repository.store import store

    found = []
    for ioc in store.get_all("iocs"):
        if ioc.type == "DNS" and not _reserved_host(ioc.value):
            found.append(f"S1 DNS indicator {ioc.value}")
        if ioc.type == "URL" and not _reserved_host(urlparse(ioc.value).hostname or ""):
            found.append(f"S1 URL indicator {ioc.value}")
    for ioc in store.get_all("xdr_iocs"):
        if ioc.type == "domain_name" and not _reserved_host(ioc.indicator):
            found.append(f"Cortex domain indicator {ioc.indicator}")
        if ioc.type == "ip" and ipaddress.ip_address(ioc.indicator).is_global:
            found.append(f"Cortex IP indicator {ioc.indicator}")
    for indicator in store.get_all("mde_indicators"):
        if (indicator.indicatorType == "IpAddress"
                and ipaddress.ip_address(indicator.indicatorValue).is_global):
            found.append(f"Defender IP indicator {indicator.indicatorValue}")
    fleet = {ep.endpoint_name for ep in store.get_all("xdr_endpoints")}
    for log in store.get_all("xdr_audit_logs"):
        if log.host_name and log.host_name not in fleet:
            found.append(f"Cortex audit host {log.host_name}")
    return found


class TestSeedNamesNoRealHost:
    """Indicators, public addresses and audited hosts stay reserved or ours."""

    def test_this_install(self, client: TestClient) -> None:
        from repository.store import store

        # The sweep must have something to look at, or it proves nothing.
        assert any(i.type in ("DNS", "URL") for i in store.get_all("iocs"))
        assert {i.type for i in store.get_all("xdr_iocs")} >= {"ip", "domain_name"}
        assert any(log.host_name for log in store.get_all("xdr_audit_logs"))
        assert not _violations(), _violations()

    def test_other_draws(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        from infrastructure import seed

        try:
            for value in (7, 1337, 2024):
                monkeypatch.setattr(seed, "SEED", value)
                seed.generate_all()
                assert not _violations(), (value, _violations())
        finally:
            monkeypatch.undo()
            seed.generate_all()
