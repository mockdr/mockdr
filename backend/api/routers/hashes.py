from fastapi import APIRouter

from repository.blocklist_repo import blocklist_repo

router = APIRouter(tags=["Hashes"])


def _lookup_hash(hash_value: str) -> dict:
    """Look up a hash against the blocklist and return the verdict payload."""
    for item in blocklist_repo.list_all():
        if item.get("value", "").lower() == hash_value.lower():
            return {
                "data": {
                    "verdict": "blacklisted",
                    "confidence": "n/a",
                    "source": item.get("source", "user"),
                }
            }
    return {"data": {"verdict": "undefined", "confidence": "n/a", "source": "cloud"}}


@router.get("/hashes/{hash_value}/reputation")
def get_hash_reputation(hash_value: str) -> dict:
    """Return the reputation for a given file hash value.

    This is the canonical path used by XSOAR and the real S1 API.
    """
    return _lookup_hash(hash_value)


@router.get("/hashes/{hash_value}/verdict")
def get_hash_verdict(hash_value: str) -> dict:
    """Return the verdict for a given file hash value (legacy alias)."""
    return _lookup_hash(hash_value)
