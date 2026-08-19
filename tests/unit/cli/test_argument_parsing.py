"""
Tests for the CLI's argument surface.

The parser is the contract the README documents, so these assert on the names
a user types rather than on argparse internals: a renamed subcommand should
fail here and not in someone's terminal.
"""

from pathlib import Path

import pytest

from network_defender.cli.main import build_parser, main


def test_every_documented_command_is_accepted() -> None:
    parser = build_parser()

    for command in ("sensor", "api", "replay", "version"):
        argv = [command, "x.pcap"] if command == "replay" else [command]

        assert parser.parse_args(argv).command == command


def test_replay_takes_a_path() -> None:
    args = build_parser().parse_args(["replay", "captures/scan.pcap"])

    assert args.pcap == Path("captures/scan.pcap")


def test_api_host_and_port_default_to_the_configuration() -> None:
    args = build_parser().parse_args(["api"])

    assert args.host is None
    assert args.port is None


def test_api_flags_override_the_configuration() -> None:
    args = build_parser().parse_args(["api", "--host", "127.0.0.1", "--port", "9000", "--reload"])

    assert (args.host, args.port, args.reload) == ("127.0.0.1", 9000, True)


def test_no_command_prints_help_and_fails() -> None:
    assert main([]) == 2


def test_version_is_printed(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert "network-defender" in capsys.readouterr().out


def test_an_unknown_command_is_rejected() -> None:
    with pytest.raises(SystemExit):
        main(["sniff-everything"])
