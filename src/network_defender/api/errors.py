"""
Structured error handling.

Data Setup:  Handlers registered on the app by the factory.
Data Input:  Exceptions raised anywhere in request handling.
Data Output: A single, consistent error body for every failure.

Why handlers rather than per-route try/except
---------------------------------------------
FastAPI's defaults emit three different shapes: `{"detail": "..."}` for
HTTPException, a list of objects for validation errors, and an HTML traceback
page for anything unhandled. A client would need three parsers, and the
traceback leaks internals. These handlers normalise all of it to
`{"error": {"code", "message", "detail"}}`.

Unhandled exceptions are logged in full and reported as a generic 500. The
stack trace belongs in the operator's logs, not in an HTTP response.
"""

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("network_defender.api")

# Stable, machine-readable error codes. Clients branch on these, not on prose.
CODE_NOT_FOUND = "not_found"
CODE_VALIDATION_ERROR = "validation_error"
CODE_UNAUTHORISED = "unauthorised"
CODE_CONFLICT = "conflict"
CODE_INTERNAL_ERROR = "internal_error"


class ApiError(Exception):
    """Base class for errors that map onto a specific HTTP response."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    code: str = CODE_INTERNAL_ERROR

    def __init__(self, message: str, detail: Any = None) -> None:
        """
        Initialise the error.

        Args:
            message: Human-readable explanation, safe to return to a client.
            detail:  Optional structured context.
        """
        super().__init__(message)
        self.message = message
        self.detail = detail


class NotFoundError(ApiError):
    """A requested resource does not exist."""

    status_code = status.HTTP_404_NOT_FOUND
    code = CODE_NOT_FOUND


class UnauthorisedError(ApiError):
    """Authentication is required and was missing or invalid."""

    status_code = status.HTTP_401_UNAUTHORIZED
    code = CODE_UNAUTHORISED


class ConflictError(ApiError):
    """The request cannot be applied in the current state."""

    status_code = status.HTTP_409_CONFLICT
    code = CODE_CONFLICT


def error_body(code: str, message: str, detail: Any = None) -> dict[str, Any]:
    """
    Build the canonical error body.

    Args:
        code:    Stable error code.
        message: Human-readable explanation.
        detail:  Optional structured context.

    Returns:
        A dict matching the ErrorResponse schema.
    """
    return {"error": {"code": code, "message": message, "detail": detail}}


def register_error_handlers(app: FastAPI) -> None:
    """
    Install handlers that normalise every failure to one shape.

    Args:
        app: The FastAPI application to configure.
    """

    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        """Render a deliberately raised domain error."""
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(exc.code, exc.message, exc.detail),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        """Reshape framework HTTPExceptions (404 routing, 405, …)."""
        code = CODE_NOT_FOUND if exc.status_code == status.HTTP_404_NOT_FOUND else "http_error"
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(code, str(exc.detail)),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Return field-level validation failures in the standard envelope."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=error_body(
                CODE_VALIDATION_ERROR,
                "Request validation failed.",
                _readable_errors(exc),
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        """Log the trace and return a generic 500; never leak internals."""
        logger.exception("Unhandled error serving request: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_body(CODE_INTERNAL_ERROR, "An internal error occurred."),
        )


def _readable_errors(exc: RequestValidationError) -> list[dict[str, Any]]:
    """Reduce Pydantic's verbose error objects to field/message/type triples."""
    return [
        {
            "field": ".".join(str(part) for part in error.get("loc", ())),
            "message": error.get("msg", ""),
            "type": error.get("type", ""),
        }
        for error in exc.errors()
    ]
