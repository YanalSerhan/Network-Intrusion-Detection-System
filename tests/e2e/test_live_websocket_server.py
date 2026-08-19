"""
End-to-end test that the live WebSocket works on the server we actually ship.

This exists because the whole suite passed against a server that answered
every WebSocket upgrade with 404. Starlette's TestClient implements the
protocol itself, so the unit and integration tests for /ws/live were green
while uvicorn — which needs a separate protocol library and had none declared
as a dependency — refused every real connection. The dashboard takes its
counters, recent alerts and top talkers from that socket, so it rendered as an
empty shell in any real deployment.

The lesson generalises: a transport that the test double provides is a
transport nobody has tested. This one starts the real command, over a real
socket, from a subprocess.
"""

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from websockets.sync.client import connect

STARTUP_TIMEOUT_SECONDS = 60.0
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    """Return a port the operating system says is free."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_until_serving(port: int, process: subprocess.Popen[bytes]) -> None:
    """Block until the port accepts connections, or fail with the server's log."""
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail(f"API exited early with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return
        except OSError:
            time.sleep(0.5)
    pytest.fail(f"API did not start within {STARTUP_TIMEOUT_SECONDS:g}s")


@pytest.fixture()
def served_api(tmp_path: Path) -> Iterator[int]:
    """Run `network-defender api` against a throwaway database."""
    port = _free_port()
    process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "network_defender", "api", "--port", str(port)],
        cwd=PROJECT_ROOT,
        env={
            "PATH": "/usr/bin:/bin",
            "DATABASE_URL": f"sqlite:///{tmp_path / 'live.db'}",
            "HOME": str(tmp_path),
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_until_serving(port, process)
        yield port
    finally:
        process.terminate()
        process.wait(timeout=30)


def test_the_live_socket_accepts_a_real_connection(served_api: int) -> None:
    with connect(f"ws://127.0.0.1:{served_api}/ws/live", open_timeout=30) as socket_client:
        frame = json.loads(socket_client.recv(timeout=30))

    assert "type" in frame
