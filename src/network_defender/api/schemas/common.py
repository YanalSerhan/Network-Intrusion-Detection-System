"""
Shared API schemas: pagination and errors.

Data Setup:  No I/O; pure response shapes.
Data Input:  Domain models from the SDK.
Data Output: JSON bodies returned to clients.

Every list endpoint returns the same envelope and every failure returns the
same error body. Clients can then write one pagination helper and one error
handler instead of one per endpoint, and the OpenAPI schema stays coherent.
"""

from pydantic import BaseModel, Field

from network_defender.constants import ALERT_QUERY_DEFAULT_LIMIT

#: Hard ceiling on page size. Without it a client can ask for everything and
#: turn one request into an unbounded query and response body.
MAX_PAGE_SIZE = 500


class PaginationParams(BaseModel):
    """Validated pagination inputs shared by every list endpoint."""

    limit: int = Field(
        default=ALERT_QUERY_DEFAULT_LIMIT,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="Maximum number of items to return.",
    )
    offset: int = Field(default=0, ge=0, description="Number of items to skip.")


class PageMeta(BaseModel):
    """Pagination metadata attached to every list response."""

    limit: int = Field(description="Page size that was applied.")
    offset: int = Field(description="Number of items skipped.")
    count: int = Field(description="Number of items in this page.")
    total: int | None = Field(
        default=None,
        description="Total items matching the filter, when cheaply countable.",
    )
    has_more: bool = Field(description="True if another page is likely available.")


def build_meta(count: int, limit: int, offset: int, total: int | None = None) -> PageMeta:
    """
    Build pagination metadata for a page of results.

    Concrete page models are used rather than a generic `Page[T]` so OpenAPI
    emits named components (`AlertPage`) instead of mangled generic names
    (`Page_AlertSummary_`), which generated clients read far better.

    Args:
        count:  Number of items in this page.
        limit:  Page size that was requested.
        offset: Offset that was requested.
        total:  Total matching items, if known.

    Returns:
        Populated PageMeta.
    """
    has_more = (offset + count) < total if total is not None else count == limit
    return PageMeta(limit=limit, offset=offset, count=count, total=total, has_more=has_more)


class ErrorDetail(BaseModel):
    """The body of every error response."""

    code: str = Field(description="Stable, machine-readable error code.")
    message: str = Field(description="Human-readable explanation.")
    detail: object | None = Field(
        default=None, description="Optional structured context, e.g. field validation errors."
    )


class ErrorResponse(BaseModel):
    """Envelope wrapping an error, so success and failure bodies differ clearly."""

    error: ErrorDetail = Field(description="Details of what went wrong.")
