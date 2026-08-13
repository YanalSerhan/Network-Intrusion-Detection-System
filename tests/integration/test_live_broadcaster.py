"""Tests for connection bookkeeping and broadcaster lifecycle."""

import asyncio

import pytest

from network_defender.api.live.broadcaster import LiveBroadcaster
from network_defender.api.live.connections import ConnectionManager
from network_defender.api.live.payloads import (
    build_error_frame,
)
from network_defender.sdk.sdk import NetworkDefenderSDK

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


def test_broadcaster_start_and_stop(readonly_sdk: NetworkDefenderSDK) -> None:
    async def scenario() -> None:
        broadcaster = LiveBroadcaster(readonly_sdk, poll_seconds=0.01)
        broadcaster.start()
        assert broadcaster.is_running

        broadcaster.start()  # idempotent
        await broadcaster.stop()
        assert not broadcaster.is_running

        await broadcaster.stop()  # safe when already stopped

    asyncio.run(scenario())


def test_idle_deployments_issue_no_queries(
    readonly_sdk: NetworkDefenderSDK, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nobody watching, the poller must not touch the database."""
    calls: list[int] = []
    monkeypatch.setattr(readonly_sdk, "list_alerts", lambda **_: calls.append(1) or [])

    async def scenario() -> None:
        broadcaster = LiveBroadcaster(readonly_sdk, poll_seconds=0.01)
        broadcaster.start()
        await asyncio.sleep(0.08)
        await broadcaster.stop()

    asyncio.run(scenario())
    assert calls == []
