"""Write-only application commands for the HTTP request audit log."""
from repository.request_log_repo import request_log_repo


def clear_request_logs() -> dict:
    """Delete all request log entries.

    Returns:
        Dict with ``data.affected`` indicating the number of deleted entries.
    """
    affected = len(request_log_repo.list_recent())
    request_log_repo.clear()
    return {"data": {"affected": affected}}
