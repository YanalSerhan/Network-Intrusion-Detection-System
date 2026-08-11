"""
/health endpoints.

Data Setup:  SDK injected per request.
Data Input:  None.
Data Output: Liveness and readiness payloads.

Liveness and readiness are separate on purpose. Liveness answers "is this
process running?" and must not touch the database — if it did, a database
blip would make an orchestrator kill and restart healthy API pods, turning a
dependency problem into an outage. Readiness answers "can this process serve
requests?" and does check the database, so a failing instance is removed from
the load balancer without being killed.

These endpoints are deliberately unauthenticated: an orchestrator probing them
has no credentials, and they expose no alert data.
"""

from fastapi import APIRouter, Response, status

from ...constants import PROJECT_VERSION
from ..dependencies import SdkDep
from ..schemas.operations import ComponentHealth, HealthResponse, LivenessResponse

router = APIRouter(prefix="/health", tags=["health"])

#: Components the API needs in order to serve requests. Capture and detection
#: run in the sensor container, so their absence here is expected, not a fault.
REQUIRED_COMPONENTS = ("database", "alerting")


@router.get("", response_model=HealthResponse, summary="Readiness check")
def readiness(sdk: SdkDep, response: Response) -> HealthResponse:
    """
    Report whether this instance can serve requests.

    Returns 503 when a required component is unhealthy, so an orchestrator
    removes the instance from rotation rather than sending it traffic.
    """
    raw = sdk.get_health()["components"]
    components = {
        name: ComponentHealth(
            status=str(detail.get("status", "unknown")),
            detail={k: v for k, v in detail.items() if k != "status"},
        )
        for name, detail in raw.items()
    }

    healthy = all(
        components[name].status == "ok" for name in REQUIRED_COMPONENTS if name in components
    )
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return HealthResponse(
        status="ok" if healthy else "degraded",
        version=PROJECT_VERSION,
        components=components,
    )


@router.get("/live", response_model=LivenessResponse, summary="Liveness check")
def liveness() -> LivenessResponse:
    """
    Report that the process is up.

    Touches nothing: a database outage must not cause healthy API instances to
    be restarted in a loop.
    """
    return LivenessResponse(status="alive")
