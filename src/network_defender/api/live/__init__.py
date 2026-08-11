"""
Live dashboard streaming (Milestone 11).

One server-side poller reads new alerts from the database and fans them out to
every connected WebSocket client, so database load stays constant regardless of
how many dashboards are open (ADR 8).
"""

from .broadcaster import LiveBroadcaster
from .connections import ConnectionManager
from .payloads import build_alert_frame, build_error_frame, build_stats_frame

__all__ = [
    "ConnectionManager",
    "LiveBroadcaster",
    "build_alert_frame",
    "build_error_frame",
    "build_stats_frame",
]
