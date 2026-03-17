"""XDR distributions seeder -- pre-seeds agent distribution packages."""
from __future__ import annotations

from domain.xdr_distribution import XdrDistribution
from infrastructure.seeders.xdr_shared import XDR_AGENT_VERSIONS, rand_epoch_ms, xdr_id
from repository.xdr_distribution_repo import xdr_distribution_repo

_PACKAGES: list[dict[str, str]] = [
    {"name": "Windows Standard Agent", "platform": "windows", "package_type": "standalone"},
    {"name": "Windows Server Agent", "platform": "windows", "package_type": "standalone"},
    {"name": "macOS Agent", "platform": "macos", "package_type": "standalone"},
    {"name": "Linux Agent (DEB)", "platform": "linux", "package_type": "deb"},
    {"name": "Linux Agent (RPM)", "platform": "linux", "package_type": "rpm"},
]


def seed_xdr_distributions() -> None:
    """Pre-seed ~5 XDR agent distribution packages."""
    for i, pkg in enumerate(_PACKAGES):
        xdr_distribution_repo.save(XdrDistribution(
            distribution_id=xdr_id("DIST"),
            name=pkg["name"],
            platform=pkg["platform"],
            package_type=pkg["package_type"],
            status="ready",
            agent_version=XDR_AGENT_VERSIONS[i % len(XDR_AGENT_VERSIONS)],
            creation_timestamp=rand_epoch_ms(180),
        ))
