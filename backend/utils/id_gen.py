import secrets
import threading

_lock = threading.Lock()


def new_id() -> str:
    """Generate a SentinelOne-style 19-digit numeric ID (thread-safe)."""
    with _lock:
        return str(10**17 + secrets.randbelow(9 * 10**17))
