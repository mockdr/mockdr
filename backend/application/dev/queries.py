"""Read-only application queries for dev tooling: stats and token listing."""
from repository.store import store
from repository.user_repo import user_repo


def get_stats() -> dict:
    """Return record counts for every store collection.

    Returns:
        Dict with ``data`` mapping each collection name to its record count.
    """
    return {"data": {
        "agents":               store.count("agents"),
        "threats":              store.count("threats"),
        "alerts":               store.count("alerts"),
        "sites":                store.count("sites"),
        "groups":               store.count("groups"),
        "activities":           store.count("activities"),
        "exclusions":           store.count("exclusions"),
        "iocs":                 store.count("iocs"),
        "firewall_rules":       store.count("firewall_rules"),
        "device_control_rules": store.count("device_control_rules"),
    }}


def list_tokens() -> dict:
    """Return all active API tokens stored in the mock.

    Returns:
        Dict with ``data`` containing the list of token records.
    """
    return {"data": user_repo.list_tokens()}
