"""Tests for the server-side poller that turns new alerts into frames."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from network_defender.api.live.broadcaster import LiveBroadcaster
from network_defender.api.live.payloads import (
    FRAME_ALERTS,
    FRAME_STATS,
    build_stats_frame,
)
from network_defender.constants import Severity
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert
from tests.fixtures.constants import PUBLIC_IP


def _alert(name: str = "TcpPortScanDetector", when: datetime | None = None) -> Alert:
    stamp = when or datetime.now(UTC)
    return Alert(
        timestamp=stamp,
        last_seen=stamp,
        severity=Severity.HIGH,
        rule_triggered=name,
        src_ip=PUBLIC_IP,
        description="seeded",
    )


# --------------------------------------------------------------------------
# Polling
# --------------------------------------------------------------------------


def test_poll_broadcasts_only_new_alerts(readonly_sdk: NetworkDefenderSDK) -> None:
    broadcaster = LiveBroadcaster(readonly_sdk)
    readonly_sdk._alert_service.repository.save(_alert(when=datetime.now(UTC) - timedelta(hours=1)))

    # Nothing newer than the watermark, so nothing is broadcast.
    assert asyncio.run(broadcaster.poll_once()) == []

    readonly_sdk._alert_service.repository.save(_alert("SynScanDetector"))
    frames = asyncio.run(broadcaster.poll_once())

    assert [frame["type"] for frame in frames] == [FRAME_ALERTS, FRAME_STATS]
    assert frames[0]["initial"] is False
    assert frames[0]["alerts"][0]["rule_triggered"] == "SynScanDetector"


def test_the_same_alert_is_not_sent_twice(readonly_sdk: NetworkDefenderSDK) -> None:
    broadcaster = LiveBroadcaster(readonly_sdk)
    readonly_sdk._alert_service.repository.save(_alert())

    assert asyncio.run(broadcaster.poll_once())
    assert asyncio.run(broadcaster.poll_once()) == []


def test_a_failing_query_does_not_kill_the_poller(
    readonly_sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    broadcaster = LiveBroadcaster(readonly_sdk)

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(readonly_sdk, "list_alerts", explode)
    assert asyncio.run(broadcaster.poll_once()) == []


def test_stats_frame_degrades_instead_of_raising(
    readonly_sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing chart beats a dead dashboard."""

    def explode() -> None:
        raise RuntimeError("counters unavailable")

    monkeypatch.setattr(readonly_sdk, "get_alert_statistics", explode)
    frame = build_stats_frame(readonly_sdk)

    assert frame["type"] == FRAME_STATS
    assert frame["total_alerts"] == 0
