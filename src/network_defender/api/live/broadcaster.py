"""
Live alert broadcaster.

Data Setup:  SDK and poll interval injected; one broadcaster per application.
Data Input:  New alerts observed in the database.
Data Output: JSON frames pushed to every connected WebSocket client.

Why one poller for all clients
------------------------------
The API reads from the database the sensor writes to (ADR 8), so "live" means
polling. Polling *per client* would multiply database load by the number of
open dashboards — ten analysts would mean ten times the queries for identical
data. A single background task polls once per interval and fans the result out,
so database load is constant regardless of how many browsers are watching.

The poller only runs while at least one client is connected, so an idle
deployment issues no queries at all.
"""

import asyncio
import contextlib
from datetime import UTC, datetime
from typing import Any

from ...constants import LIVE_POLL_SECONDS, LIVE_RECENT_ALERT_LIMIT
from ...sdk.sdk import NetworkDefenderSDK
from ...shared.base import LoggableMixin
from .connections import ConnectionManager
from .payloads import build_alert_frame, build_stats_frame


class LiveBroadcaster(LoggableMixin):
    """Polls for new alerts and broadcasts them to subscribed clients."""

    def __init__(
        self,
        sdk: NetworkDefenderSDK,
        connections: ConnectionManager | None = None,
        poll_seconds: float = LIVE_POLL_SECONDS,
    ) -> None:
        """
        Initialise the broadcaster.

        Args:
            sdk:          The SDK used to read alerts and statistics.
            connections:  Client registry; a new one is created if omitted.
            poll_seconds: Seconds between database polls.
        """
        self._sdk = sdk
        self.connections = connections or ConnectionManager()
        self._poll_seconds = poll_seconds
        self._task: asyncio.Task[None] | None = None
        # Only alerts newer than this are broadcast. Seeded at start so a
        # client connecting does not receive the entire alert history.
        self._watermark: datetime = datetime.now(UTC)

    @property
    def is_running(self) -> bool:
        """True while the polling task is active."""
        return self._task is not None and not self._task.done()

    def start(self) -> None:
        """Start polling. A second call is a no-op."""
        if self.is_running:
            return
        self._watermark = datetime.now(UTC)
        self._task = asyncio.create_task(self._run(), name="live-broadcaster")

    async def stop(self) -> None:
        """Cancel polling and wait for the task to unwind."""
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    def snapshot(self) -> list[dict[str, Any]]:
        """
        Return the frames a newly connected client should receive first.

        Without this a client sees an empty dashboard until the next alert
        happens, which on a quiet network could be a long time.
        """
        recent = self._sdk.list_alerts(limit=LIVE_RECENT_ALERT_LIMIT)
        return [
            build_stats_frame(self._sdk),
            build_alert_frame(list(reversed(recent)), initial=True),
        ]

    async def poll_once(self) -> list[dict[str, Any]]:
        """
        Run a single poll cycle and broadcast anything new.

        Exposed separately from the loop so tests can drive it deterministically
        instead of sleeping.

        Returns:
            The frames that were broadcast.
        """
        frames: list[dict[str, Any]] = []
        try:
            fresh = await asyncio.to_thread(
                self._sdk.list_alerts, since=self._watermark, limit=LIVE_RECENT_ALERT_LIMIT
            )
        except Exception as exc:  # noqa: BLE001 - a query failure must not kill the loop
            self.logger.error("Live poll failed: %s", exc)
            return frames

        new_alerts = [alert for alert in fresh if alert.timestamp > self._watermark]
        if new_alerts:
            self._watermark = max(alert.timestamp for alert in new_alerts)
            frames.append(build_alert_frame(list(reversed(new_alerts))))
            frames.append(build_stats_frame(self._sdk))

        for frame in frames:
            await self.connections.broadcast(frame)
        return frames

    async def _run(self) -> None:
        """Poll while clients are connected, idling otherwise."""
        while True:
            await asyncio.sleep(self._poll_seconds)
            if self.connections.is_empty:
                continue
            await self.poll_once()
