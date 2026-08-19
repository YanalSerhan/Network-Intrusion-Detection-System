"""
Tests for what each subcommand does.

The SDK is substituted here — starting it for real is the end-to-end suite's
job, and these are about the wiring: that `api` reads its defaults from
configuration rather than hardcoding them, that `replay` uses the start mode
that needs no privileges, and that a missing file fails without a traceback.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from network_defender.cli.commands import run_api, run_replay, run_sensor


def test_a_missing_capture_fails_without_starting_anything(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch("network_defender.cli.commands.NetworkDefenderSDK") as sdk:
        assert run_replay(tmp_path / "absent.pcap", settle=0.0) == 1

    assert not sdk.create.called
    assert "No such capture" in capsys.readouterr().out


def test_replay_uses_the_start_mode_that_needs_no_privileges(tmp_path: Path) -> None:
    capture = tmp_path / "present.pcap"
    capture.write_bytes(b"")

    with patch("network_defender.cli.commands.NetworkDefenderSDK") as factory:
        sdk = factory.create.return_value
        sdk.list_alerts.return_value = []

        assert run_replay(capture, settle=0.0) == 0

    sdk.start_offline.assert_called_once()
    assert not sdk.start.called
    sdk.start_capture_from_pcap.assert_called_once_with(capture)
    sdk.stop.assert_called_once()


def test_replay_stops_the_sdk_even_when_replay_raises(tmp_path: Path) -> None:
    capture = tmp_path / "broken.pcap"
    capture.write_bytes(b"")

    with patch("network_defender.cli.commands.NetworkDefenderSDK") as factory:
        sdk = factory.create.return_value
        sdk.start_capture_from_pcap.side_effect = ValueError("truncated")

        with pytest.raises(ValueError, match="truncated"):
            run_replay(capture, settle=0.0)

    sdk.stop.assert_called_once()


def test_api_falls_back_to_the_configured_host_and_port() -> None:
    with patch("uvicorn.run") as serve, patch(
        "network_defender.cli.commands.load_app_config"
    ) as config:
        config.return_value.api = MagicMock(host="10.0.0.1", port=9999, reload=False)

        assert run_api(host=None, port=None, reload=False) == 0

    assert serve.call_args.kwargs["host"] == "10.0.0.1"
    assert serve.call_args.kwargs["port"] == 9999


def test_api_flags_win_over_the_configuration() -> None:
    with patch("uvicorn.run") as serve, patch(
        "network_defender.cli.commands.load_app_config"
    ) as config:
        config.return_value.api = MagicMock(host="10.0.0.1", port=9999, reload=False)

        run_api(host="127.0.0.1", port=8001, reload=True)

    assert serve.call_args.kwargs["host"] == "127.0.0.1"
    assert serve.call_args.kwargs["port"] == 8001
    assert serve.call_args.kwargs["reload"] is True


def test_the_api_is_served_as_a_factory() -> None:
    with patch("uvicorn.run") as serve, patch("network_defender.cli.commands.load_app_config"):
        run_api(host="127.0.0.1", port=8001, reload=False)

    # create_app builds the app; passing the module attribute directly would
    # serve the function object rather than calling it.
    assert serve.call_args.kwargs["factory"] is True


def test_the_sensor_stops_cleanly_when_signalled() -> None:
    with patch("network_defender.cli.commands.NetworkDefenderSDK") as factory, patch(
        "network_defender.cli.commands._wait_for_signal"
    ):
        sdk = factory.create.return_value

        assert run_sensor() == 0

    sdk.start.assert_called_once()
    sdk.stop.assert_called_once()
