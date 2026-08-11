"""
WebSocket frame construction.

Data Setup:  No state.
Data Input:  Domain Alerts and SDK statistics.
Data Output: JSON-serialisable frames with a discriminating `type` field.

Every frame carries a `type` so the client dispatches on one field rather than
guessing from shape — the same reason the REST error contract has a `code`.
Alerts are sent as the same `AlertSummary` shape the REST list endpoint
returns, so the client has one alert type rather than two that drift apart.
"""

from datetime import UTC, datetime
from typing import Any

from ...sdk.sdk import NetworkDefenderSDK
from ...services.alerts.models import Alert
from ..schemas.alerts import AlertSummary

FRAME_ALERTS = "alerts"
FRAME_STATS = "stats"
FRAME_ERROR = "error"


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()


def build_alert_frame(alerts: list[Alert], initial: bool = False) -> dict[str, Any]:
    """
    Build a frame carrying new alerts.

    Args:
        alerts:  Alerts to send, oldest first.
        initial: True for the backfill sent on connect, so the client can
            replace its list rather than prepending to it.

    Returns:
        A JSON-serialisable frame.
    """
    return {
        "type": FRAME_ALERTS,
        "sent_at": _now(),
        "initial": initial,
        "alerts": [AlertSummary.from_domain(alert).model_dump(mode="json") for alert in alerts],
    }


def build_stats_frame(sdk: NetworkDefenderSDK) -> dict[str, Any]:
    """
    Build a frame carrying current counters.

    Args:
        sdk: The SDK to read statistics from.

    Returns:
        A JSON-serialisable frame. Counter failures degrade to zeroes rather
        than dropping the connection: a missing chart is better than a dead
        dashboard.
    """
    try:
        stats = sdk.get_alert_statistics()
        breakdown = sdk.get_alert_breakdown()
    except Exception:  # noqa: BLE001 - degrade, never break the stream
        stats = {"total_alerts": 0, "by_severity": {}}
        breakdown = {"top_talkers": {}, "protocol_distribution": {}, "packets_retained": 0}

    return {
        "type": FRAME_STATS,
        "sent_at": _now(),
        "total_alerts": stats["total_alerts"],
        "alerts_by_severity": stats["by_severity"],
        "packets_retained": breakdown["packets_retained"],
        "top_talkers": breakdown["top_talkers"],
        "protocol_distribution": breakdown["protocol_distribution"],
    }


def build_error_frame(message: str) -> dict[str, Any]:
    """
    Build a frame reporting a stream-level problem.

    Args:
        message: Human-readable explanation.

    Returns:
        A JSON-serialisable frame.
    """
    return {"type": FRAME_ERROR, "sent_at": _now(), "message": message}
