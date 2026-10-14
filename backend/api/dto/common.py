from typing import Any

from pydantic import BaseModel


class Pagination(BaseModel):
    """Pagination metadata included in list responses."""

    totalItems: int
    nextCursor: str | None = None


class SingleResponse(BaseModel):
    """Standard S1 API single-item response envelope."""

    data: Any


class FilterBody(BaseModel):
    """Request body with filter and data dicts for threat/alert bulk operations."""

    filter: dict = {}
    data: dict = {}


class BulkActionBody(BaseModel):
    """Request body for bulk agent actions supporting both ids and filter."""

    ids: list[str] | None = None
    filter: dict | None = None
    data: dict | list | None = None
