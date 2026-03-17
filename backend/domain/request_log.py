"""Domain dataclass for HTTP request audit log entries."""
from dataclasses import dataclass


@dataclass
class RequestLog:
    """Represents a single audited HTTP request.

    Attributes:
        id: Unique identifier for this log entry.
        timestamp: ISO 8601 timestamp of when the request completed.
        method: HTTP method (GET, POST, etc.).
        path: URL path of the request.
        query_string: Raw query string, empty string if none.
        status_code: HTTP response status code.
        duration_ms: Request duration in milliseconds.
        token_hint: Last 8 characters of the ApiToken header value,
            or empty string if the request was unauthenticated.
    """

    id: str
    timestamp: str
    method: str
    path: str
    query_string: str
    status_code: int
    duration_ms: int
    token_hint: str
