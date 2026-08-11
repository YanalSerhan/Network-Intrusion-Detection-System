"""
Shared HTTP transport for threat intel providers.

Data Setup:  Timeout from constants; no per-provider HTTP policy.
Data Input:  URL, query params and headers assembled by a provider.
Data Output: Parsed JSON body.

This function is the *only* place providers touch the network, and it is always
invoked through `ApiGatekeeper.execute(...)` — never called directly — so rate
limiting, queueing and retries apply uniformly (ADR 3).

It deliberately raises on any failure: the gatekeeper needs an exception to
trigger its retry/backoff logic, and the calling provider converts the final
failure into a ProviderResult so the system still fails open.
"""

from typing import Any

import httpx

from network_defender.constants import TI_HTTP_TIMEOUT_SECONDS


class ProviderHttpError(RuntimeError):
    """Raised when an upstream provider returns an error or unparsable body."""


def get_json(
    url: str,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = TI_HTTP_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """
    Perform a GET request and return the decoded JSON object.

    Args:
        url:     Absolute URL to request.
        params:  Query string parameters.
        headers: Request headers (e.g. an API key header).
        timeout: Total timeout in seconds.

    Returns:
        The decoded JSON body as a dict.

    Raises:
        ProviderHttpError: On transport failure, non-2xx status, malformed JSON,
            or a JSON body that is not an object.
    """
    try:
        response = httpx.get(url, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPStatusError as exc:
        raise ProviderHttpError(
            f"HTTP {exc.response.status_code} from {url}"
        ) from exc
    except httpx.HTTPError as exc:
        raise ProviderHttpError(f"Request to {url} failed: {exc}") from exc
    except ValueError as exc:
        raise ProviderHttpError(f"Malformed JSON from {url}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ProviderHttpError(f"Expected a JSON object from {url}, got {type(payload).__name__}")
    return payload
