"""Microsoft Defender for Endpoint File/Domain/IP info API router.

Implements MDE enrichment endpoints for files (by hash), domains, and
IP addresses — both info and statistics.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from api.mde_auth import require_mde_auth
from application.mde_file_info import queries as file_queries

router = APIRouter(tags=["MDE File/Domain/IP Info"])


# ── Files ────────────────────────────────────────────────────────────────────


@router.get("/api/files/{file_hash}")
def get_file_info(
    file_hash: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get file information for a given SHA1 or SHA256 hash."""
    return file_queries.get_file_info(file_hash)


@router.get("/api/files/{file_hash}/stats")
def get_file_stats(
    file_hash: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get file statistics for a given SHA1 or SHA256 hash."""
    return file_queries.get_file_stats(file_hash)


# ── Domains ──────────────────────────────────────────────────────────────────


@router.get("/api/domains/{domain}")
def get_domain_info(
    domain: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get domain information."""
    return file_queries.get_domain_info(domain)


@router.get("/api/domains/{domain}/stats")
def get_domain_stats(
    domain: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get domain statistics."""
    return file_queries.get_domain_stats(domain)


# ── IP Addresses ─────────────────────────────────────────────────────────────


@router.get("/api/ips/{ip}")
def get_ip_info(
    ip: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get IP address information."""
    return file_queries.get_ip_info(ip)


@router.get("/api/ips/{ip}/stats")
def get_ip_stats(
    ip: str,
    _: dict = Depends(require_mde_auth),
) -> dict:
    """Get IP address statistics."""
    return file_queries.get_ip_stats(ip)
