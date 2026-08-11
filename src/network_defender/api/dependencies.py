"""
Request dependencies: SDK access, pagination and authentication.

Data Setup:  The SDK is built once at application startup and stored on
             `app.state`, not per request.
Data Input:  Request headers and query parameters.
Data Output: Injected SDK handle, validated pagination, verified caller.

Why one SDK for the process
---------------------------
Building an SDK opens a database engine and constructs every service. Doing
that per request would create a connection pool per request. It is built once
in the lifespan handler and shared; the SDK's own components are thread-safe.
"""

from typing import Annotated

from fastapi import Depends, Query, Request

from ..constants import ALERT_QUERY_DEFAULT_LIMIT, ENV_API_KEY
from ..sdk.sdk import NetworkDefenderSDK
from ..shared.secrets import get_secret
from .errors import UnauthorisedError
from .schemas.common import MAX_PAGE_SIZE, PaginationParams

API_KEY_HEADER = "X-API-Key"


def get_sdk(request: Request) -> NetworkDefenderSDK:
    """
    Return the process-wide SDK instance.

    Args:
        request: The incoming request, carrying application state.

    Returns:
        The shared NetworkDefenderSDK.
    """
    sdk: NetworkDefenderSDK = request.app.state.sdk
    return sdk


def get_pagination(
    limit: Annotated[
        int,
        Query(ge=1, le=MAX_PAGE_SIZE, description="Maximum number of items to return."),
    ] = ALERT_QUERY_DEFAULT_LIMIT,
    offset: Annotated[int, Query(ge=0, description="Number of items to skip.")] = 0,
) -> PaginationParams:
    """
    Validate and package pagination query parameters.

    Bounds are enforced by FastAPI, so an out-of-range page size fails with a
    422 before any query runs rather than loading an unbounded result set.

    Args:
        limit:  Requested page size.
        offset: Requested offset.

    Returns:
        Validated PaginationParams.
    """
    return PaginationParams(limit=limit, offset=offset)


def require_api_key(request: Request) -> None:
    """
    Enforce the API key when one is configured.

    Authentication is **off when no key is set**, which keeps local development
    frictionless while making production a single environment variable away.
    A deployment that forgets to set the key is therefore open — the /config
    endpoint reports whether a key is configured so that is visible rather than
    silent.

    Args:
        request: The incoming request.

    Raises:
        UnauthorisedError: If a key is configured and the header is missing or wrong.
    """
    expected = get_secret(ENV_API_KEY)
    if not expected:
        return

    supplied = request.headers.get(API_KEY_HEADER)
    if supplied != expected:
        raise UnauthorisedError(
            f"A valid {API_KEY_HEADER} header is required.",
            detail={"header": API_KEY_HEADER},
        )


#: Reusable annotated types, so routes read as `sdk: SdkDep` rather than
#: repeating Depends(...) at every signature.
SdkDep = Annotated[NetworkDefenderSDK, Depends(get_sdk)]
PaginationDep = Annotated[PaginationParams, Depends(get_pagination)]
AuthDep = Depends(require_api_key)
