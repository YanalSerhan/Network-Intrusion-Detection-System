"""
Live dashboard streaming (Milestone 11).

One server-side poller reads new alerts from the database and fans them out to
every connected WebSocket client, so database load stays constant regardless of
how many dashboards are open (ADR 8).
"""

from network_defender.api.live.broadcaster import LiveBroadcaster
from network_defender.api.live.connections import ConnectionManager
from network_defender.api.live.payloads import (
    build_alert_frame,
    build_error_frame,
    build_stats_frame,
)

__all__ = [
    "ConnectionManager",
    "LiveBroadcaster",
    "build_alert_frame",
    "build_error_frame",
    "build_stats_frame",
]
