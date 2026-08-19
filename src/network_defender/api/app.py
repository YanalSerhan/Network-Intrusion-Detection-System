"""
FastAPI application factory.

Data Setup:  Builds the SDK once in the lifespan handler and stores it on
             app.state for dependency injection.
Data Input:  HTTP requests.
Data Output: JSON responses defined by the routers.

Topology
--------
This process serves the API; it does **not** run packet capture. That follows
the deployment model in PLAN.md §4: the engine and API are separate containers
sharing a database. The consequences are deliberate — the API needs no
CAP_NET_RAW, and it can be restarted or scaled horizontally without dropping
packets, because nothing is capturing here.

The database service is started so migrations run and repositories are usable;
capture, detection and enrichment services are not, so the API never competes
with the sensor for a network interface.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ..constants import API_PREFIX, API_TITLE, PROJECT_VERSION
from ..observability import setup_logging
from ..sdk.sdk import NetworkDefenderSDK
from .errors import register_error_handlers
from .live.broadcaster import LiveBroadcaster
from .middleware import CorrelationMiddleware
from .routers import (
    alerts,
    config,
    dashboard,
    health,
    live,
    packets,
    rules,
    statistics,
)
from .security_headers import SecurityHeadersMiddleware

DESCRIPTION = """
REST API for **Network Defender**, a modular Python network intrusion
detection system.

Every endpoint delegates to the internal SDK: no business logic lives in a
route handler, so the API, CLI and dashboard cannot drift apart.

**Authentication** — when an `API_KEY` is configured, requests must carry an
`X-API-Key` header. With no key configured, authentication is disabled so
local development works out of the box.
"""

TAGS_METADATA = [
    {"name": "alerts", "description": "Query and triage security alerts."},
    {"name": "packets", "description": "Packets retained as alert evidence."},
    {"name": "statistics", "description": "Traffic and alert aggregates."},
    {"name": "rules", "description": "Inspect, toggle and reload detection rules."},
    {"name": "health", "description": "Liveness and readiness probes."},
    {"name": "config", "description": "Non-secret runtime configuration."},
    {"name": "live", "description": "WebSocket stream of alerts and counters."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Build the SDK on startup and release it on shutdown.

    Only the database is started: this process reads what the sensor wrote and
    must not open a capture interface of its own.
    """
    setup_logging(service="network-defender-api")
    sdk = NetworkDefenderSDK.create()
    sdk.start_readonly()
    app.state.sdk = sdk

    broadcaster = LiveBroadcaster(sdk)
    broadcaster.start()
    app.state.broadcaster = broadcaster
    try:
        yield
    finally:
        await broadcaster.stop()
        sdk.stop_readonly()


def create_app(sdk: NetworkDefenderSDK | None = None) -> FastAPI:
    """
    Build the FastAPI application.

    Args:
        sdk: Pre-built SDK to use instead of constructing one. Tests inject a
            fixture-configured instance; passing one disables the lifespan so
            the caller keeps control of the service lifecycle.

    Returns:
        A configured FastAPI application.
    """
    app = FastAPI(
        title=API_TITLE,
        description=DESCRIPTION,
        version=PROJECT_VERSION,
        openapi_tags=TAGS_METADATA,
        lifespan=None if sdk is not None else lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    if sdk is not None:
        app.state.sdk = sdk
        # Tests and embedders that supply an SDK own the lifecycle, so the
        # broadcaster is attached but left un-started; poll_once() can be
        # driven directly instead of waiting on a timer.
        app.state.broadcaster = LiveBroadcaster(sdk)

    # Added before the routers so every request, including failures handled by
    # the error handlers, runs inside a correlation scope.
    app.add_middleware(CorrelationMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    register_error_handlers(app)

    for router in (alerts, packets, statistics, rules, health, config):
        app.include_router(router.router, prefix=API_PREFIX)

    # The live socket and the dashboard sit outside /api/v1: one is a transport,
    # the other a user interface, and neither is part of the data contract.
    app.include_router(live.router)
    app.include_router(dashboard.router)

    return app
