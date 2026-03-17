"""Repository for RequestLog entries backed by InMemoryStore."""
from dataclasses import asdict

from domain.request_log import RequestLog
from repository.store import store


class RequestLogRepository:
    """Append-only repository for HTTP request audit log entries.

    Does not subclass ``Repository[T]`` because no ``save``/``delete``/``get``
    semantics are needed — only append and list operations.
    """

    def append(self, log: RequestLog) -> None:
        """Persist a new request log entry at the head of the log.

        Args:
            log: The ``RequestLog`` to persist.
        """
        store.append_request_log(log.id, asdict(log))

    def list_recent(self) -> list[RequestLog]:
        """Return all request log entries in newest-first order.

        Returns:
            List of ``RequestLog`` instances ordered newest-first.
        """
        return [RequestLog(**record) for record in store.list_request_logs()]

    def clear(self) -> None:
        """Remove all request log entries from the store."""
        store.clear_request_logs()


request_log_repo = RequestLogRepository()
