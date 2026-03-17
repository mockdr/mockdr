from typing import Any

from pydantic import BaseModel


class Pagination(BaseModel):
    """Pagination metadata included in list responses."""

    totalItems: int
    nextCursor: str | None = None


class ListResponse(BaseModel):
    """Standard S1 API list response envelope."""

    data: list[Any]
    pagination: Pagination


class SingleResponse(BaseModel):
    """Standard S1 API single-item response envelope."""

    data: Any


class AffectedResponse(BaseModel):
    """Standard S1 API action response indicating affected record count."""

    data: dict  # {"affected": N}


class ErrorDetail(BaseModel):
    """Details of a single API error."""

    code: int
    detail: str
    title: str


class ErrorResponse(BaseModel):
    """Standard S1 API error response envelope."""

    errors: list[ErrorDetail]
    data: None = None


class FilterBody(BaseModel):
    """Request body with filter and data dicts for threat/alert bulk operations."""

    filter: dict = {}
    data: dict = {}


class BulkActionBody(BaseModel):
    """Request body for bulk agent actions supporting both ids and filter."""

    ids: list[str] | None = None
    filter: dict | None = None
    data: dict | list | None = None
