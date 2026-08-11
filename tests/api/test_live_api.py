"""Tests for the WebSocket live feed."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from network_defender.api.live.broadcaster import LiveBroadcaster
from network_defender.api.live.connections import ConnectionManager
from network_defender.api.live.payloads import (
    FRAME_ALERTS,
    FRAME_STATS,
    build_error_frame,
    build_stats_frame,
)
from network_defender.constants import ENV_API_KEY, Severity
from network_defender.sdk.sdk import NetworkDefenderSDK
from network_defender.services.alerts.models import Alert

from .conftest import PUBLIC_IP

WS_URL = "/ws/live"


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
# Handshake and snapshot
# --------------------------------------------------------------------------


def test_client_receives_a_snapshot_on_connect(client: TestClient, seeded_alert: Alert) -> None:
    """A new dashboard must be populated immediately, not on the next alert."""
    with client.websocket_connect(WS_URL) as ws:
        stats = ws.receive_json()
        alerts = ws.receive_json()

    assert stats["type"] == FRAME_STATS
    assert stats["total_alerts"] == 1

    assert alerts["type"] == FRAME_ALERTS
    assert alerts["initial"] is True
    assert alerts["alerts"][0]["rule_triggered"] == "TcpPortScanDetector"


def test_snapshot_on_an_empty_system(client: TestClient) -> None:
    with client.websocket_connect(WS_URL) as ws:
        assert ws.receive_json()["total_alerts"] == 0
        assert ws.receive_json()["alerts"] == []


def test_alert_frames_match_the_rest_summary_shape(
    client: TestClient, seeded_alert: Alert
) -> None:
    """One alert type on the client, not two that drift apart."""
    rest = client.get("/api/v1/alerts").json()["items"][0]

    with client.websocket_connect(WS_URL) as ws:
        ws.receive_json()
        streamed = ws.receive_json()["alerts"][0]

    assert streamed.keys() == rest.keys()
    assert streamed["alert_id"] == rest["alert_id"]


# --------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------


def test_connection_is_open_when_no_key_is_configured(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ENV_API_KEY, raising=False)
    with client.websocket_connect(WS_URL) as ws:
        assert ws.receive_json()["type"] == FRAME_STATS


def test_connection_is_refused_without_a_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rejected before accept(), so an unauthorised client sees no data at all."""
    monkeypatch.setenv(ENV_API_KEY, "expected-key")

    with pytest.raises(Exception):  # noqa: B017 - starlette raises on a refused handshake
        with client.websocket_connect(WS_URL) as ws:
            ws.receive_json()


def test_connection_is_accepted_with_the_right_token(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ENV_API_KEY, "expected-key")
    with client.websocket_connect(f"{WS_URL}?token=expected-key") as ws:
        assert ws.receive_json()["type"] == FRAME_STATS


# --------------------------------------------------------------------------
# Polling
# --------------------------------------------------------------------------


def test_poll_broadcasts_only_new_alerts(sdk: NetworkDefenderSDK) -> None:
    broadcaster = LiveBroadcaster(sdk)
    sdk._alert_service.repository.save(_alert(when=datetime.now(UTC) - timedelta(hours=1)))

    # Nothing newer than the watermark, so nothing is broadcast.
    assert asyncio.run(broadcaster.poll_once()) == []

    sdk._alert_service.repository.save(_alert("SynScanDetector"))
    frames = asyncio.run(broadcaster.poll_once())

    assert [frame["type"] for frame in frames] == [FRAME_ALERTS, FRAME_STATS]
    assert frames[0]["initial"] is False
    assert frames[0]["alerts"][0]["rule_triggered"] == "SynScanDetector"


def test_the_same_alert_is_not_sent_twice(sdk: NetworkDefenderSDK) -> None:
    broadcaster = LiveBroadcaster(sdk)
    sdk._alert_service.repository.save(_alert())

    assert asyncio.run(broadcaster.poll_once())
    assert asyncio.run(broadcaster.poll_once()) == []


def test_a_failing_query_does_not_kill_the_poller(
    sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    broadcaster = LiveBroadcaster(sdk)

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(sdk, "list_alerts", explode)
    assert asyncio.run(broadcaster.poll_once()) == []


def test_stats_frame_degrades_instead_of_raising(
    sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing chart beats a dead dashboard."""

    def explode() -> None:
        raise RuntimeError("counters unavailable")

    monkeypatch.setattr(sdk, "get_alert_statistics", explode)
    frame = build_stats_frame(sdk)

    assert frame["type"] == FRAME_STATS
    assert frame["total_alerts"] == 0


# --------------------------------------------------------------------------
# Connection manager
# --------------------------------------------------------------------------


class _FakeSocket:
    """Records frames; optionally fails to simulate a dead client."""

    def __init__(self, fail: bool = False) -> None:
        self.frames: list[dict[str, object]] = []
        self.fail = fail

    async def accept(self) -> None:
        return None

    async def send_json(self, frame: dict[str, object]) -> None:
        if self.fail:
            raise RuntimeError("socket closed")
        self.frames.append(frame)


def test_broadcast_reaches_every_client() -> None:
    manager = ConnectionManager()
    sockets = [_FakeSocket(), _FakeSocket()]

    async def scenario() -> int:
        for socket in sockets:
            await manager.connect(socket)  # type: ignore[arg-type]
        return await manager.broadcast({"type": "test"})

    assert asyncio.run(scenario()) == 2
    assert all(socket.frames for socket in sockets)


def test_a_dead_client_does_not_block_the_others() -> None:
    """One closed laptop lid must not stop delivery to everyone else."""
    manager = ConnectionManager()
    dead, alive = _FakeSocket(fail=True), _FakeSocket()

    async def scenario() -> int:
        await manager.connect(dead)  # type: ignore[arg-type]
        await manager.connect(alive)  # type: ignore[arg-type]
        return await manager.broadcast({"type": "test"})

    assert asyncio.run(scenario()) == 1
    assert manager.count == 1  # the dead client was dropped
    assert alive.frames


def test_disconnect_removes_the_client() -> None:
    manager = ConnectionManager()
    socket = _FakeSocket()

    async def scenario() -> None:
        await manager.connect(socket)  # type: ignore[arg-type]
        assert manager.count == 1
        await manager.disconnect(socket)  # type: ignore[arg-type]

    asyncio.run(scenario())
    assert manager.is_empty


def test_error_frame_shape() -> None:
    frame = build_error_frame("stream unavailable")
    assert frame["type"] == "error"
    assert frame["message"] == "stream unavailable"


# --------------------------------------------------------------------------
# Lifecycle
# --------------------------------------------------------------------------


def test_broadcaster_start_and_stop(sdk: NetworkDefenderSDK) -> None:
    async def scenario() -> None:
        broadcaster = LiveBroadcaster(sdk, poll_seconds=0.01)
        broadcaster.start()
        assert broadcaster.is_running

        broadcaster.start()  # idempotent
        await broadcaster.stop()
        assert not broadcaster.is_running

        await broadcaster.stop()  # safe when already stopped

    asyncio.run(scenario())


def test_idle_deployments_issue_no_queries(
    sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nobody watching, the poller must not touch the database."""
    calls: list[int] = []
    monkeypatch.setattr(sdk, "list_alerts", lambda **_: calls.append(1) or [])

    async def scenario() -> None:
        broadcaster = LiveBroadcaster(sdk, poll_seconds=0.01)
        broadcaster.start()
        await asyncio.sleep(0.08)
        await broadcaster.stop()

    asyncio.run(scenario())
    assert calls == []
