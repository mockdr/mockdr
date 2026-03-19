"""Read-only application queries for the HTTP request audit log."""
from dataclasses import asdict

from repository.request_log_repo import request_log_repo


def list_request_logs(limit: int = 100) -> dict:
    """Return the most recent request log entries.

    Args:
        limit: Maximum number of entries to return.  Defaults to 100.

    Returns:
        Dict with ``data`` list and ``pagination.totalItems`` count.
    """
    all_logs = request_log_repo.list_recent()
    limited = all_logs[:limit]
    return {
        "data": [asdict(log) for log in limited],
        "pagination": {"totalItems": len(all_logs)},
    }
