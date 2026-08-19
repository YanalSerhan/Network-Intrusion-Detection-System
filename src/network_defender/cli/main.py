"""
The `network-defender` command.

Data Setup:  None.
Data Input:  Command-line arguments.
Data Output: A process exit code.

Three verbs, because there are three ways to run this system and they need
different privileges: `sensor` captures live and wants CAP_NET_RAW, `api`
serves HTTP and deliberately has no capture capability at all, and `replay`
runs the whole detection pipeline over a file and needs neither.

Until this existed the project had no entry point. The README's usage section
held a placeholder, and the only way to run a detector was to write a script
against the SDK — which meant the documented way to try the system was
untested, because there was nothing to test.
"""

import argparse
from pathlib import Path

from ..constants import PROJECT_VERSION
from .commands import REPLAY_SETTLE_SECONDS, run_api, run_replay, run_sensor, run_version


def build_parser() -> argparse.ArgumentParser:
    """
    Build the argument parser.

    Returns:
        A parser with one subcommand per way of running the system.
    """
    parser = argparse.ArgumentParser(
        prog="network-defender",
        description="Network Defender — a modular network intrusion detection system.",
    )
    parser.add_argument("--version", action="version", version=PROJECT_VERSION)
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    commands.add_parser("sensor", help="capture live traffic and detect (needs CAP_NET_RAW)")

    api = commands.add_parser("api", help="serve the REST API and the dashboard")
    api.add_argument("--host", default=None, help="bind address (default: api.host in config)")
    api.add_argument("--port", type=int, default=None, help="bind port (default: api.port)")
    api.add_argument("--reload", action="store_true", help="auto-reload on change (dev only)")

    replay = commands.add_parser("replay", help="replay a .pcap through the pipeline")
    replay.add_argument("pcap", type=Path, help="capture file to replay")
    replay.add_argument(
        "--settle",
        type=float,
        default=REPLAY_SETTLE_SECONDS,
        help="seconds to wait after the last packet for the evaluation timer",
    )

    commands.add_parser("version", help="print the version")
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    Parse arguments and run the chosen command.

    Args:
        argv: Arguments to parse. Defaults to sys.argv[1:].

    Returns:
        Process exit code; 2 when no command was given, matching argparse.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "sensor":
        return run_sensor()
    if args.command == "api":
        return run_api(args.host, args.port, args.reload)
    if args.command == "replay":
        return run_replay(args.pcap, args.settle)
    if args.command == "version":
        return run_version()

    parser.print_help()
    return 2
