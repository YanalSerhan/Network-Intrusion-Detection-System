"""
What each subcommand does.

Data Setup:  Reads config/setup.json through the usual pipeline.
Data Input:  Parsed arguments.
Data Output: A process exit code, and whatever the command prints.

Kept apart from the argument parsing next door so a command can be called
directly from a test without going through argv, and so neither file has to
grow when the other does.

Every command goes through the SDK. Nothing here touches a service, which is
the same rule the REST API follows — if the CLI could reach past the SDK the
two entry points would eventually disagree about what "start" means.
"""

import signal
import time
from pathlib import Path
from types import FrameType

from ..constants import PROJECT_VERSION
from ..sdk.sdk import NetworkDefenderSDK
from ..shared.config import load_app_config

#: How long a replay waits after the last packet before reporting. The
#: detectors decide on a timer, so a replay that exits immediately reads an
#: empty database and reports that nothing was detected.
REPLAY_SETTLE_SECONDS = 6.0


def _wait_for_signal() -> None:
    """Block until SIGINT or SIGTERM, so the sensor stops cleanly."""
    stopping = False

    def handle(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    while not stopping:
        time.sleep(0.5)


def run_sensor() -> int:
    """
    Run live capture and detection until interrupted.

    Needs CAP_NET_RAW (or root) and an interface that exists; the interface is
    `capture.interface` in config/setup.json.

    Returns:
        Process exit code.
    """
    sdk = NetworkDefenderSDK.create()
    sdk.start()
    try:
        print("Sensor running. Press Ctrl-C to stop.")
        _wait_for_signal()
    finally:
        sdk.stop()
    return 0


def run_api(host: str | None, port: int | None, reload: bool) -> int:
    """
    Serve the REST API and the dashboard.

    Args:
        host:   Bind address; defaults to `api.host` in config/setup.json.
        port:   Bind port; defaults to `api.port`.
        reload: Auto-reload on source changes. Development only.

    Returns:
        Process exit code.
    """
    import uvicorn

    config = load_app_config().api
    uvicorn.run(
        "network_defender.api.app:create_app",
        factory=True,
        host=host or config.host,
        port=port or config.port,
        reload=reload or config.reload,
    )
    return 0


def run_replay(path: Path, settle: float) -> int:
    """
    Replay a capture file through the full pipeline and print what fired.

    Uses the offline start mode, so this needs no privileges and no network
    interface — the replay path feeds the same packet callback the live
    sniffer does.

    Args:
        path:   The .pcap to replay.
        settle: Seconds to wait after the last packet, so the detectors'
                evaluation timer has fired at least once.

    Returns:
        0 if the file was replayed, 1 if it does not exist.
    """
    if not path.exists():
        print(f"No such capture: {path}")
        return 1

    sdk = NetworkDefenderSDK.create()
    sdk.start_offline()
    try:
        sdk.start_capture_from_pcap(path)
        time.sleep(settle)
        alerts = sdk.list_alerts(limit=100)
        print(f"\n{len(alerts)} alert(s) from {path.name}:\n")
        for alert in alerts:
            print(
                f"  {alert.severity:<8} {alert.rule_triggered:<26} "
                f"confidence {alert.confidence:.2f}  {alert.src_ip or '-'}"
            )
            print(f"           {alert.description}")
    finally:
        sdk.stop()
    return 0


def run_version() -> int:
    """Print the version and exit."""
    print(f"network-defender {PROJECT_VERSION}")
    return 0
