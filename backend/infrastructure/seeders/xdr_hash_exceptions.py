"""XDR hash exceptions seeder -- pre-seeds blocklist and allowlist entries."""
from __future__ import annotations

from domain.xdr_hash_exception import XdrHashException
from infrastructure.seeders.xdr_shared import rand_epoch_ms, xdr_id
from repository.xdr_hash_exception_repo import xdr_hash_exception_repo

# Known-malicious hashes for blocklist
_BLOCKLIST_HASHES: list[tuple[str, str]] = [
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Empty file hash — common dropper indicator"),
    ("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", "Known Emotet payload"),
    ("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "TrickBot loader hash"),
    ("a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", "Cobalt Strike beacon"),
    ("6dcd4ce23d88e2ee9568ba546c007c63d9131c1b1234567890abcdef12345678", "Ransomware variant LockBit 3.0"),
    ("2fd4e1c67a2d28fced849ee1bb76e7391b93eb121234567890abcdef12345678", "Mimikatz credential dumper"),
]

# Known-safe hashes for allowlist
_ALLOWLIST_HASHES: list[tuple[str, str]] = [
    ("aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb00190", "Internal IT admin tool — signed"),
    ("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", "Vulnerability scanner agent"),
    ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "Corporate backup agent"),
    ("d8e8fca2dc0f896fd7cb4cb0031ba249e5e44c2e1234567890abcdef12345678", "SCCM deployment package"),
]


def seed_xdr_hash_exceptions() -> None:
    """Pre-seed 10 XDR hash exception records (6 blocklist + 4 allowlist)."""
    for hash_value, comment in _BLOCKLIST_HASHES:
        xdr_hash_exception_repo.save(XdrHashException(
            exception_id=xdr_id("HEX"),
            hash=hash_value,
            list_type="blocklist",
            comment=comment,
            created_at=rand_epoch_ms(90),
        ))

    for hash_value, comment in _ALLOWLIST_HASHES:
        xdr_hash_exception_repo.save(XdrHashException(
            exception_id=xdr_id("HEX"),
            hash=hash_value,
            list_type="allowlist",
            comment=comment,
            created_at=rand_epoch_ms(90),
        ))
